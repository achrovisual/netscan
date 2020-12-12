#!/usr/bin/env python3

import argparse, time, scanner, ipv4, logging, sys
from threading import Thread

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scappy.interactive").setLevel(logging.ERROR)
logging.getLogger("scappy.loading").setLevel(logging.ERROR)

try:
    from scapy.all import *
except ImportError:
    print("Scapy library for Python is not installed on your system. Run 'pip install --pre scapy[basic]' to install the library.")
    print("For more information, visit https://scapy.readthedocs.io/en/latest/installation.html to isntall Scapy.")
    exit(0)

def main():
    start = time.time()

    # Arg Parsing
    parser = argparse.ArgumentParser(description = '', formatter_class = argparse.RawTextHelpFormatter)

    parser.add_argument("H", nargs="?", help = "Target Host IP or URL")
    parser.add_argument("-p", "--p", help = "Target Port")
    parser.add_argument("-i", "--i", action = 'store_true', help = "Perform Ping Sweep")
    parser.add_argument("-c", "--c", help = "Number of ICMP ECHO Requests to be sent for Ping Sweep", type = int)
    parser.add_argument("-t", "--t", action = 'store_true', help = "Perform TCP Connect Scan")
    parser.add_argument("-s", "--s", action = 'store_true', help = "Perform TCP SYN Scan")
    parser.add_argument("-x", "--x", action = 'store_true', help = "Perform TCP XMAS Scan")
    parser.add_argument("-f", "--f", action = 'store_true', help = "Perform TCP FIN Scan")
    parser.add_argument("-n", "--n", action = 'store_true', help = "Perform TCP NULL Scan")
    parser.add_argument("-a", "--a", action = 'store_true', help = "Perform TCP ACK Scan")
    parser.add_argument("-ALL", "--ALL", action = 'store_true', help = "Perform ALL TCP Port Scans")
    parser.add_argument("-T", "--T", action = 'store_true', help = "Show time spent to compelete the scan")
    parser.add_argument("-v", "--v", action = 'store_true', help = "Show program description")

    args = parser.parse_args()

    if args.v:
        print("netscan by Eugenio Pastoral\n")
        print("netscan is a TCP port scanning and ping sweep tool that uses Scapy to craft and send out appropriate packets. It can detect open, closed, filtered, and unfiltered ports. It can also detect live hosts.\n")
        print("NOTE: In order to ensure that the program is going to work correctly, please install the latest version of Scapy.")
    else:
        ip = args.H
        end = 2

        if args.i:
            end = 1
        elif args.t:
            type = 1
        elif args.s:
            type = 2
        elif args.x:
            type = 3
        elif args.f:
            type = 4
        elif args.n:
            type = 5
        elif args.a:
            type = 6
        elif args.ALL:
            end = 7
        port = args.p

        if not ipv4.validate_ip(ip):
            print('\nIP address is missing or invalid. Please try again.')
            parser.print_help()
            exit(0)

        # Check args present and set variables
        if not args.i:
            if (port == None):
                print('\nPlease specify a valid port to perform a port scan.')
                parser.print_help()
                exit(0)

        if args.i:
            scanner.ping(ip, args.c)

        for type in range (1, end):
            scanner.portscan(ip, port, type)
            print('\n=============================================')

        end = time.time()

        if args.T:
            print('\nCompleted scan in ' + str(round((end - start), 4)) + 's.')
        else:
            print('\nScan complete.')

if __name__ == '__main__':
    try:
        t = Thread(target=main)
        t.daemon = True
        t.start()
        while True: time.sleep(100)
    except KeyboardInterrupt as e:
        sys.exit(0)
