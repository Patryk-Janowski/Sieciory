import struct
import random
import socket

class ICMPLib:

    ICMP_ECHO_REQUEST = 8
    ICMP_CODE = socket.getprotobyname('icmp')
    TIMEOUT: float = 2

    def findChecksum(self, data):
        '''
        Oblicza sumę kontrolną dla pakietu ICMP. Wymagana do sprawdzenia integralności pakietu.
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
        Tworzy pakiet ICMP korzystając z identyfikatora, numeru sekwencji oraz przesyłanych danych.
        Zwraca stworzony nagłówek ICMP połączony z przesyłanymi danymi.
        '''
        checksum = 0

        # tymczasowy nagłówek ICMP do obliczenia sumy kontrolnej
        header = struct.pack('!2B3H', self.ICMP_ECHO_REQUEST, 0, checksum,
            id, sequence)

        checksum = self.findChecksum(header + payload)

        # docelowy nagłówek ICMP
        header = struct.pack('!2B3H', self.ICMP_ECHO_REQUEST, 0, checksum,
            id, sequence)

        return header + payload

    def buildEchoRequestPacket(self):
        '''
        Tworzy pakiet typu EchoRequest korzystając z funkcji createPacket z wylosowanym numerem pakietu i pustymi przesyłanymi danymi.
        Zwraca gotowy pakiet typu ICMP Echo Request.
        '''
        packet_id = int(random.random() * 65535)
        data = b""
        return self.createPacket(packet_id, 1, data)
    
    def getIcmpSocket(self):
        '''
        Tworzy gniazdo surowe korzystające z rodziny adresów AF_INET i protokołu ICMP. Ustawia timeout i przypisuje gniazdo do dostępnego portu.
        Zwraca skonfigurowane gniazdo.
        '''
        icmp_sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP
            )
        
        icmp_sock.settimeout(self.TIMEOUT)
        icmp_sock.bind(("", 0))
        return icmp_sock
    
    def setSockTTl(self, sock: socket.socket, ttl): 
        '''
        Ustawia przekazaną w argumencie wartość pola Time To Live dla gniazda przekazanego w argumencie.
        '''
        sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        return True
    
    def sendEchoRequest(self, sock: socket.socket, dest_addr):
        '''
        Wysyła pakiet ICMP Echo Request na adres wskazany w argumencie korzystając z wybranego gniazda.
        '''
        packet = self.buildEchoRequestPacket()
        while packet:
            sent = sock.sendto(packet, (dest_addr, 12345)) # numer portu nie ma w tym wypadku znaczenia
            packet = packet[sent:]