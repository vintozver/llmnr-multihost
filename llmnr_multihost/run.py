#!python3

import sys
import socket
import pyroute2
import pyroute2.ipdb
from . import service
from threading import Thread, Event, Lock

import logging
logging.basicConfig(level=logging.INFO)


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
        logging.info('Trying to add interface %d:%s' % (index, name))

        self.update_addresses(index, name)
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
        logging.info('Trying to remove interface %d:<>' % index)

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
        # Clear cached addresses
        del self.address_map_ipv4[index]
        del self.address_map_ipv6[index]

    def get_addresses_ipv4(self, ifindex):
        return self.address_map_ipv4[ifindex]

    def get_addresses_ipv6(self, ifindex):
        return self.address_map_ipv6[ifindex]

    def update_addresses(self, ifindex, ifname):
        logging.info('Updating interface addresses %d:%s' % (ifindex, ifname))
        def yield_ipaddr(family):
            for ifaddr in pyroute2.IPRoute().get_addr(family=family, index=ifindex):
                if 'attrs' in ifaddr:
                    for ifaddr_attr_key, ifaddr_attr_value in ifaddr['attrs']:
                        if ifaddr_attr_key == 'IFA_ADDRESS':
                            yield ifaddr_attr_value
        self.address_map_ipv4[ifindex] = list(yield_ipaddr(socket.AF_INET))
        self.address_map_ipv6[ifindex] = list(yield_ipaddr(socket.AF_INET6))

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

    def ipdb_callback(ipdb, msg, action):
        logging.debug('NETLINK event: %s, %s' % (repr(msg), action))

        if action == 'RTM_NEWLINK':
            ifindex = msg['index']
            ifname = ipdb.interfaces[ifindex]['ifname']
            dispatcher.add_interface(ifindex, ifname)
            return

        if action == 'RTM_DELLINK':
            ifindex = msg['index']
            dispatcher.remove_interface(ifindex)
            return

        if action in ['RTM_NEWADDR', 'RTM_DELADDR']:
            ifindex = msg['index']
            ifname = ipdb.interfaces[ifindex]['ifname']
            dispatcher.update_addresses(ifindex, ifname)
            return

    ipdb = pyroute2.IPDB()
    ipdb_cb = ipdb.register_callback(ipdb_callback)

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

    ipdb.unregister_callback(ipdb_cb)
    ipdb.release()
    dispatcher.shutdown()


if __name__ == '__main__':
    exit(main())