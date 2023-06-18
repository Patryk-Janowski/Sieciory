import struct
import random
import socket

class ICMPLib:

    ICMP_ECHO_REQUEST = 8
    ICMP_CODE = socket.getprotobyname('icmp')
    TIMEOUT: float = 2

    def findChecksum(self, data):
        '''
        Compute the checksum of an ICMP packet. Checksums are used to
        verify the integrity of packets.
        '''
        sum = 0
        data += b'\x00'

        for i in range(0, len(data) - 1, 2):
            sum += (data[i] << 8) + data[i + 1]
            sum  = (sum & 0xffff) + (sum >> 16)

        sum = ~sum & 0xffff

        return sum

    def createPacket(self, id, sequence, payload):
        '''
        Build an ICMP packet from an identifier, a sequence number and
        a payload.

        This method returns the newly created ICMP header concatenated
        to the payload passed in parameters.

        '''
        checksum = 0

        # Temporary ICMP header to compute the checksum
        header = struct.pack('!2B3H', self.ICMP_ECHO_REQUEST, 0, checksum,
            id, sequence)

        checksum = self.findChecksum(header + payload)

        # Definitive ICMP header
        header = struct.pack('!2B3H', self.ICMP_ECHO_REQUEST, 0, checksum,
            id, sequence)

        return header + payload

    def buildEchoRequestPacket(self):
        packet_id = int(random.random() * 65535) # We have to fit the ID into 16 Bytes (unsigned short int in C) hence 65535
        data = b""
        return self.createPacket(packet_id, 1, data)
    
    def getIcmpSocket(self):
        icmp_sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP
            )
        # Set the timeout for receiving packets
        icmp_sock.settimeout(self.TIMEOUT)

        # Bind the receiver socket to any available port
        icmp_sock.bind(("", 0))

        return icmp_sock
    
    def setSockTTl(self, sock: socket.socket, ttl): 
        sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        return True
    
    def sendEchoRequest(self, sock: socket.socket, dest_addr):
        packet = self.buildEchoRequestPacket()
        while packet:
            sent = sock.sendto(packet, (dest_addr, 12345)) # Give a dummy port even though icmp protocol doesn't need one
            packet = packet[sent:]