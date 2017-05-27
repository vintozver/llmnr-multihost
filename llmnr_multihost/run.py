#!python3

from . import service
from threading import Thread, Event

import logging
logging.basicConfig(level=logging.DEBUG)


def main():
    server = service.ResolverServer()
    server6 = service.ResolverServer6()

    def resolver_server_thread(server):
        logging.info('Serving %s ...', repr(type(server)))
        server.serve_forever()

    logging.info('Creating threads')
    thread = Thread(target=resolver_server_thread, args=(server, ))
    thread.start()
    thread6 = Thread(target=resolver_server_thread, args=(server6, ))
    thread6.start()

    termination_event = Event()

    import signal

    def signal_handler(signum, frame):
        logging.warning('Received signal %s. Exiting' % signum)
        termination_event.set()

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGHUP, signal_handler)

    import time
    while True:
        try:
            if termination_event.wait(60):
                logging.info('Event triggered. Shutting down ...')
                break
            logging.info('Still working ...')
        except (InterruptedError, KeyboardInterrupt):
            logging.info('Interrupt received. Shutting down ...')
            break

    termination_event.set()
    server.shutdown()
    server6.shutdown()
    thread.join()
    thread6.join()


if __name__ == '__main__':
    exit(main())