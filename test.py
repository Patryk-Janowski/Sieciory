from TracerouteLib import Traceroute
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='Traceroute',
        description='Traces route')
    parser.add_argument('dest_name', help='destination name')          
    parser.add_argument('-i', '--send_over_icmp',action='store_true', help='send over icmp flag') 
    args = parser.parse_args()
    if args.send_over_icmp:
        print("Using ICMP echo request")
    else:
        print("Using empty UDP packets")
    tr = Traceroute(args.send_over_icmp)
    tr.traceroute(args.dest_name)
