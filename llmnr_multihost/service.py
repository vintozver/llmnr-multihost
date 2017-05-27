from . import ctypes
import struct
import socket
import socketserver
import dnslib
import netifaces
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
                struct.pack('!4sli',
                    socket.inet_pton(socket.AF_INET, '224.0.0.252'),
                    socket.INADDR_ANY,
                    0
                )
            )
        except OSError as err:
            logging.error('Failed to subscribe to IPv4 multicast. Error: %d, %s' % (err.errno, err.strerror))

    def __init__(self):
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
                struct.pack("!16sI", socket.inet_pton(socket.AF_INET6, 'FF02:0:0:0:0:0:1:3'), 0)  # struct ipv6_mreq
            )
        except OSError as err:
            logging.error('Failed to subscribe to IPv6 multicast. Error: %d, %s' % (err.errno, err.strerror))

        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO,
            struct.pack("!i", True)  # boolean value in an integer
        )

    def get_request(self):
        iface_index = None
        data, ancdata, flags, client_addr = self.socket.recvmsg(
            self.max_packet_size,
            socket.CMSG_SPACE(ctypes.sizeof(ctypes.in6_pktinfo))
        )
        for anc in ancdata:
            if anc[0] == socket.IPPROTO_IPV6 and anc[1] == socket.IPV6_PKTINFO:
                _in6_pktinfo = ctypes.in6_pktinfo.from_buffer_copy(anc[2])
                iface_index = _in6_pktinfo.ipi6_ifindex
        return (data, self.socket, iface_index), client_addr

    def __init__(self):
        super(ResolverServer6, self).__init__(('FF02:0:0:0:0:0:1:3', 5355, 0, 2), ResolverHandler)


class ResolverHandler(socketserver.BaseRequestHandler):
    def handle(self):
        packet_bytes = self.request[0]
        packet_socket = self.request[1]
        iface_index = self.request[2]
        parsed = False
        try:
            dnsreq = dnslib.DNSRecord.parse(packet_bytes)
            parsed = True
        except dnslib.DNSError:
            pass
        if parsed:
            logging.debug('IN FROM ADDRESS: %s, INTERFACE: %s, LLMNR DNS packet:\n%s' % (
                self.client_address,
                iface_index,
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

                idna = dnsreq.q.qname.idna()
                if ('dummy' in idna) or ('test' in idna):
                    dnsresp = dnsreq.reply(0, 0)
                    if dnsreq.q.qclass == dnslib.CLASS.IN:
                        if dnsreq.q.qtype == dnslib.QTYPE.AAAA:
                            if iface_index is None:
                                return

                            ifaces = netifaces.interfaces()
                            try:
                                iface = ifaces[iface_index - 1]
                            except IndexError:
                                return

                            try:
                                ifaddresses = netifaces.ifaddresses(iface)[netifaces.AF_INET6]
                            except (KeyError, ValueError):
                                return

                            for ifaddress in ifaddresses:
                                # IPv6 address may be link-local and might have interface suffix
                                ipaddress = ifaddress['addr'].split('%', 1)[0]

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

