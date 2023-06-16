# script.py
from __future__ import annotations

import socket
import sys
import time
from collections.abc import Generator
from contextlib import ExitStack
import struct
import random


ICMP_ECHO_REQUEST = 8
ICMP_CODE = socket.getprotobyname('icmp')

def findChecksum(data):
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

def create_packet(id, sequence, payload):
    '''
    Build an ICMP packet from an identifier, a sequence number and
    a payload.

    This method returns the newly created ICMP header concatenated
    to the payload passed in parameters.

    '''
    checksum = 0

    # Temporary ICMP header to compute the checksum
    header = struct.pack('!2B3H', ICMP_ECHO_REQUEST, 0, checksum,
        id, sequence)

    checksum = findChecksum(header + payload)

    # Definitive ICMP header
    header = struct.pack('!2B3H', ICMP_ECHO_REQUEST, 0, checksum,
        id, sequence)

    return header + payload

def buildPacket():
    packet_id = int(random.random() * 65535) # We have to fit the ID into 16 Bytes (unsigned short int in C) hence 65535
    data = b""
    return create_packet(packet_id, 1, data)


def traceroute(
    dest_addr: str, max_hops: int = 64, timeout: float = 2, send_over_icmp: bool = False
) -> Generator[tuple[str, float], None, None]:
    """Traceroute implementation using UDP packets.

    Args:
        dest_addr (str): The destination address.
        max_hops (int, optional): The maximum number of hops.
        Defaults to 64.
        timeout (float, optional): The timeout for receiving packets.
        Defaults to 2.

    Yields:
        Generator[tuple[str, float], None, None]: A generator that
        yields the current address and elapsed time for each hop.

    """
    send_over_icmp = False
    # ExitStack allows us to avoid multiple nested contextmanagers
    with ExitStack() as stack:
        # Create an ICMP socket connection for receiving packets
        icmp_sock = stack.enter_context(
            socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP
            )
        )

        if not send_over_icmp:
        # Create a UDP socket connection for sending packets
            tx = stack.enter_context(
                socket.socket(
                    socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP
                )
            )

        # Set the timeout for receiving packets
        icmp_sock.settimeout(timeout)

        # Bind the receiver socket to any available port
        icmp_sock.bind(("", 0))

        # Iterate over the TTL values
        for ttl in range(1, max_hops + 1):
            # Set the TTL value in the sender socket
            if not send_over_icmp:
                tx.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

                # Send an empty UDP packet to the destination address
                tx.sendto(b"", (dest_addr, 33434))
            else:
                icmp_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
                packet = buildPacket()
                # Send the packet
                while packet:
                    sent = icmp_sock.sendto(packet, (dest_addr, 12345)) # Give a dummy port even though icmp protocol doesn't need one
                    packet = packet[sent:]
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


def main() -> None:
    # Get the destination address from command-line argument
    dest_name = sys.argv[1]
    dest_addr = socket.gethostbyname(dest_name)

    # Print the traceroute header
    print(f"Traceroute to {dest_name} ({dest_addr})")
    print(
        f"{'Hop':<5s}{'IP Address':<20s}{'Hostname':<50s}{'Time (ms)':<10s}"
    )
    print("-" * 90)

    # Iterate over the traceroute results and print each hop information
    for i, (addr, elapsed_time) in enumerate(traceroute(dest_addr)):
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


if __name__ == "__main__":
    main()