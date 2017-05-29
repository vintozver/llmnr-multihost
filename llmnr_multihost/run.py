#!python3

import sys
import socket
import pyroute2
from . import service
from threading import Thread, Event, Lock

import logging
logging.basicConfig(level=logging.DEBUG)


class Dispatcher(object):
    @classmethod
    def _server_thread(cls, server):
        logging.info('Serving %s ...', repr(type(server)))
        server.serve_forever()

    def __init__(self, hostname_list):
        self.hostname_list = hostname_list
        self.address_map_ipv4 = dict()  # map ifindex->[ipaddr, ...]
        self.address_map_ipv6 = dict()  # map ifindex->[ipaddr, ...]
        self.map_lock = Lock()
        self.shutdown_event = Event()
        self.servers_ipv4 = dict()  # map ifindex->Server
        self.servers_ipv6 = dict()  # map ifindex->Server
        self.threads_ipv4 = dict()  # map ifindex->Thread
        self.threads_ipv6 = dict()  # map ifindex->Thread

    def add_interface(self, index, name):
        def yield_ipaddr(family):
            for ifaddr in pyroute2.IPRoute().get_addr(family=family, index=index):
                if 'attrs' in ifaddr:
                    for ifaddr_attr_key, ifaddr_attr_value in ifaddr['attrs']:
                        if ifaddr_attr_key == 'IFA_ADDRESS':
                            yield ifaddr_attr_value
        self.address_map_ipv4[index] = list(yield_ipaddr(socket.AF_INET))
        self.address_map_ipv6[index] = list(yield_ipaddr(socket.AF_INET6))
        with self.map_lock:
            if self.shutdown_event.is_set():
                logging.warning('Interface will NOT be added, we are shutting down')
                return

            # Perform verification
            if index in self.servers_ipv4:
                logging.error('Interface %d:%s is already served by the existing server (IPv4)' % (index, name))
                return
            if index in self.servers_ipv6:
                logging.error('Interface %d:%s is already served by the existing server (IPv6)' % (index, name))
                return
            if index in self.threads_ipv4:
                logging.error('Interface %d:%s is already served by the existing thread (IPv4)' % (index, name))
                return
            if index in self.threads_ipv6:
                logging.error('Interface %d:%s is already served by the existing thread (IPv6)' % (index, name))
                return
            # Create servers and threads
            logging.info('Creating servers for %d:%s' % (index, name))
            server_ipv4 = service.ResolverServer(self, index)
            self.servers_ipv4[index] = server_ipv4
            server_ipv6 = service.ResolverServer6(self, index)
            self.servers_ipv6[index] = server_ipv6
            logging.info('Creating threads for %d:%s' % (index, name))
            thread_ipv4 = Thread(target=self._server_thread, args=(server_ipv4, ))
            thread_ipv4.start()
            self.threads_ipv4[index] = thread_ipv4
            thread_ipv6 = Thread(target=self._server_thread, args=(server_ipv6, ))
            thread_ipv6.start()
            self.threads_ipv6[index] = thread_ipv6

    def remove_interface(self, index):
        with self.map_lock:
            if self.shutdown_event.is_set():
                logging.warning('Interface will NOT be removed, we are shutting down')
                return

            server_ipv4 = self.servers_ipv4[index]
            server_ipv6 = self.servers_ipv6[index]
            thread_ipv4 = self.threads_ipv4[index]
            thread_ipv6 = self.threads_ipv6[index]
            del self.servers_ipv4[index]
            del self.servers_ipv6[index]
            del self.threads_ipv4[index]
            del self.threads_ipv6[index]
        server_ipv4.shutdown()
        server_ipv6.shutdown()
        thread_ipv4.join()
        thread_ipv6.join()

    def get_addresses_ipv4(self, ifindex):
        return self.address_map_ipv4[ifindex]

    def get_addresses_ipv6(self, ifindex):
        return self.address_map_ipv6[ifindex]

    def update_addresses(self, ifindex):
        pass

    def shutdown(self):
        with self.map_lock:
            self.shutdown_event.set()
            for ifindex, server in self.servers_ipv4.items():
                server.shutdown()
            for ifindex, server in self.servers_ipv6.items():
                server.shutdown()
            for ifindex, thread in self.threads_ipv4.items():
                thread.join()
            for ifindex, thread in self.threads_ipv6.items():
                thread.join()


def main():
    hostname_list = sys.argv[1:]

    logging.info('Adding current interfaces')
    dispatcher = Dispatcher(hostname_list)
    for interface in pyroute2.IPRoute().get_links():
        dispatcher.add_interface(interface['index'], dict(interface['attrs'])['IFLA_IFNAME'])

    termination_event = Event()

    import signal

    def signal_handler(signum, frame):
        logging.warning('Received signal %s. Exiting' % signum)
        termination_event.set()

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGHUP, signal_handler)

    while True:
        try:
            if termination_event.wait(60):
                logging.info('Event triggered. Shutting down ...')
                break
            logging.info('Still working ...')
        except (InterruptedError, KeyboardInterrupt):
            logging.info('Interrupt received. Shutting down ...')
            break

    dispatcher.shutdown()


if __name__ == '__main__':
    exit(main())