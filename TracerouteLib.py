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
        # ExitStack allows us to avoid multiple nested contextmanagers
        with ExitStack() as stack:
            # Create an ICMP socket connection for receiving packets
            icmp_sock = stack.enter_context(self.getIcmpSocket())

            if not self.send_over_icmp:
            # Create a UDP socket connection for sending packets
                tx = stack.enter_context(
                    socket.socket(
                        socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP
                    )
                )

            # Iterate over the TTL values
            for ttl in range(1, self.MAX_HOPS + 1):
                # Set the TTL value in the sender socket
                if self.send_over_icmp:
                    self.setSockTTl(icmp_sock, ttl)
                    self.sendEchoRequest(icmp_sock, dest_addr)
                else:
                    tx.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                    tx.sendto(b"", (dest_addr, 33434))
                try:
                    # Start the timer
                    start_time = time.perf_counter_ns()

                    # Receive the response packet and extract the source address
                    _, curr_addr = icmp_sock.recvfrom(512)
                    curr_addr = curr_addr[0]

                    # Stop the timer and calculate the elapsed time
                    end_time = time.perf_counter_ns()
                    elapsed_time = (end_time - start_time) / 1e6
                except socket.error:
                    # If an error occurs while receiving the packet, set the
                    # address and elapsed time as None
                    curr_addr = None
                    elapsed_time = None

                # Yield the current address and elapsed time
                yield curr_addr, elapsed_time

                # Break the loop if the destination address is reached
                if curr_addr == dest_addr:
                    break
    
    def printHeader(self, dest_addr, dest_name):
        # Print the traceroute header
        print(f"Traceroute to {dest_name} ({dest_addr})")
        print(
            f"{'Hop':<5s}{'IP Address':<20s}{'Hostname':<50s}{'Time (ms)':<10s}"
        )
        print("-" * 90)

    def traceroute(self, dest_name):
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
