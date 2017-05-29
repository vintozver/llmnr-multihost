import functools
import operator
import struct
import socket
import socketserver
import dnslib
import logging


class ResolverServer(socketserver.UDPServer):
    address_family = socket.AF_INET
    allow_reuse_address = True

    def server_bind(self):
        s = self.socket
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(self.server_address)
        try:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,  # struct ip_mreqn
                struct.pack('4sli',
                    socket.inet_pton(socket.AF_INET, self.server_address[0]),
                    socket.INADDR_ANY,
                    self.ifindex
                )
            )
        except OSError as err:
            logging.error('Failed to subscribe to IPv4 multicast. Error: %d, %s' % (err.errno, err.strerror))

    def __init__(self, dispatcher, ifindex):
        self.dispatcher = dispatcher
        self.hostname_list = dispatcher.hostname_list
        self.ifindex = ifindex
        super(ResolverServer, self).__init__(('224.0.0.252', 5355), ResolverHandler)


class ResolverServer6(socketserver.UDPServer):
    address_family = socket.AF_INET6
    allow_reuse_address = True

    def server_bind(self):
        s = self.socket
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(self.server_address)
        try:
            s.setsockopt(socket.IPPROTO_IPV6, 20,  # IPV6_ADD_MEMBERSHIP
                struct.pack("16si", socket.inet_pton(socket.AF_INET6, self.server_address[0]), self.ifindex)  # struct ipv6_mreq
            )
        except OSError as err:
            logging.error('Failed to subscribe to IPv6 multicast. Error: %d, %s' % (err.errno, err.strerror))

    def __init__(self, dispatcher, ifindex):
        self.dispatcher = dispatcher
        self.hostname_list = dispatcher.hostname_list
        self.ifindex = ifindex
        super(ResolverServer6, self).__init__(('FF02:0:0:0:0:0:1:3', 5355, 0, ifindex), ResolverHandler)


class ResolverHandler(socketserver.BaseRequestHandler):
    def handle(self):
        packet_bytes = self.request[0]
        packet_socket = self.request[1]
        parsed = False
        try:
            dnsreq = dnslib.DNSRecord.parse(packet_bytes)
            parsed = True
        except dnslib.DNSError:
            pass
        if parsed:
            logging.debug('IN FROM ADDRESS: %s, INTERFACE: %s, LLMNR DNS packet:\n%s' % (
                self.client_address,
                self.server.ifindex,
                repr(dnsreq)
            ))
            if dnslib.OPCODE.get(dnsreq.header.opcode) != 'QUERY':
                return
            if dnsreq.header.qr:
                # this is response
                if dnsreq.header.q != 1:
                    return
            else:
                # this is query
                if dnsreq.header.q != 1:
                    return
                if dnsreq.header.a != 0:
                    return
                if dnsreq.header.auth != 0:
                    return
                if dnsreq.header.aa:  # RFC 4795: flag C
                    return

                hostname = str(dnsreq.q.qname)
                if functools.reduce(
                        operator.or_,
                        (hostname == _hostname for _hostname in self.server.hostname_list),
                        False
                ):
                    dnsresp = dnsreq.reply(0, 0)
                    if dnsreq.q.qclass == dnslib.CLASS.IN:
                        if dnsreq.q.qtype == dnslib.QTYPE.AAAA:
                            for ipaddress in self.server.dispatcher.get_addresses_ipv6(self.server.ifindex):
                                dnsresp.add_answer(dnslib.RR(
                                    dnsreq.q.qname.idna(),
                                    dnslib.QTYPE.AAAA,
                                    ttl=60,
                                    rdata=dnslib.AAAA(ipaddress)
                                ))
                        else:
                            return
                    else:
                        return
                    dnsresp.header.aa = 0  # RFC 4795: flag C
                    packet_socket.sendto(dnsresp.pack(), self.client_address)
                    logging.debug('OUT TO ADDRESS: %s, LLMNR DNS packet:\n%s' % (
                        self.client_address, repr(dnsresp)
                    ))
