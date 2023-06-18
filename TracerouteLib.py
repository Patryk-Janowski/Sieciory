from IcmpLib import ICMPLib
import socket
import sys
import time
from collections.abc import Generator
from contextlib import ExitStack

class Traceroute(ICMPLib):
    
    MAX_HOPS = 64
    def __init__(self, send_over_icmp: bool = False) -> None:
        self.send_over_icmp = send_over_icmp

    def tracerouteUtil(self, dest_addr: str,) -> Generator[tuple[str, float], None, None]:
        """
        Implementacja funkcjonalności traceroute. W zależności od ustawienia zmiennej send_over_icmp korzysta z protokołu ICMP lub UDP.
        Funkcja jak argument przyjmuje adres docelowy.
        Zwraca generator zwracający obecny adres i upłynięty czas dla każdego węzła.
        """
        # użycie ExitStack umożliwia ominięcie wielu zagnieżdzonych with
        with ExitStack() as stack:
            # stworzenie gniazda nasłuchującego do odbierania ICMP Echo Reply
            icmp_sock = stack.enter_context(self.getIcmpSocket())

            if not self.send_over_icmp:
            # Stworznenie gniazda UDP do wysyłania pakietów
                tx = stack.enter_context(
                    socket.socket(
                        socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP
                    )
                )

            # Iterowanie po wartościach pola TTL
            for ttl in range(1, self.MAX_HOPS + 1):
                # Ustawianie wartości pola TTL w zależności od wybranego protokołu
                if self.send_over_icmp:
                    self.setSockTTl(icmp_sock, ttl)
                    self.sendEchoRequest(icmp_sock, dest_addr)
                else:
                    tx.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                    tx.sendto(b"", (dest_addr, 33434))

                # Obliczanie czasu dla węzła i wyciąganie adresu źródłowego z otrzymanego pakietu
                try:
                    start_time = time.perf_counter_ns()

                    _, curr_addr = icmp_sock.recvfrom(512)
                    curr_addr = curr_addr[0]

                    end_time = time.perf_counter_ns()
                    elapsed_time = (end_time - start_time) / 1e6
                except socket.error:
                    # W przypadku pojawienia się błędu ustawienie adresu i czasu na None
                    curr_addr = None
                    elapsed_time = None

                yield curr_addr, elapsed_time

                # Zakończenie pętli w momencie osiągnięcia adresu docelowego
                if curr_addr == dest_addr:
                    break
    
    def printHeader(self, dest_addr, dest_name):
        """
        Wypisuje nagłówek programu
        """
        print(f"Traceroute to {dest_name} ({dest_addr})")
        print(
            f"{'Hop':<5s}{'IP Address':<20s}{'Hostname':<50s}{'Time (ms)':<10s}"
        )
        print("-" * 90)

    def execute(self, dest_name):
        """
        Wywołuje odpowiednie funkcje i prezentuje ich wyniki w odpowiedni sposób.
        Przyjmuje adres docelowy jako argument.
        """
        dest_addr = socket.gethostbyname(dest_name)
        self.printHeader(dest_addr, dest_name)
        for i, (addr, elapsed_time) in enumerate(self.tracerouteUtil(dest_addr)):
            if addr is not None:
                try:
                    # Get the hostname corresponding to the IP address
                    host = socket.gethostbyaddr(addr)[0]
                except socket.error:
                    host = ""
                # Print the hop information
                print(
                    f"{i+1:<5d}{addr:<20s}{host:<50s}{elapsed_time:<10.3f} ms"
                )
            else:
                # Print "*" for hops with no response
                print(f"{i+1:<5d}{'*':<20s}{'*':<50s}{'*':<10s}")
