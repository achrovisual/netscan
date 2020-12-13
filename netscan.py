# Author: Eugenio Pastoral
# Course: Advanced and Offensive Security

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

    THO = parser.add_argument_group('TARGET HOST OPTIONS')
    THO.add_argument("H", nargs="?", help = "Target Host IP or URL")
    THO.add_argument("-p", "--p", help = "Target Port")

    PSO = parser.add_argument_group('PORT SCANNING OPTIONS')
    PSO.add_argument("-t", "--t", action = 'store_true', help = "Perform TCP Connect Scan")
    PSO.add_argument("-s", "--s", action = 'store_true', help = "Perform TCP SYN Scan")
    PSO.add_argument("-x", "--x", action = 'store_true', help = "Perform TCP XMAS Scan")
    PSO.add_argument("-f", "--f", action = 'store_true', help = "Perform TCP FIN Scan")
    PSO.add_argument("-n", "--n", action = 'store_true', help = "Perform TCP NULL Scan")
    PSO.add_argument("-a", "--a", action = 'store_true', help = "Perform TCP ACK Scan")
    PSO.add_argument("-ALL", "--ALL", action = 'store_true', help = "Perform ALL TCP Port Scans")

    IEO = parser.add_argument_group('PING SWEEPING OPTIONS')
    IEO.add_argument("-i", "--i", action = 'store_true', help = "Perform Ping Sweep")
    IEO.add_argument("-c", "--c", help = "Number of ICMP ECHO Requests to be sent for Ping Sweep", type = int)

    IEO = parser.add_argument_group('PROGRAM OPTIONS')
    IEO.add_argument("-T", "--T", action = 'store_true', help = "Show time spent to compelete the scan")
    IEO.add_argument("-v", "--v", action = 'store_true', help = "Show program description")

    args = parser.parse_args()

    if args.v:
        print("""
███╗░░██╗███████╗████████╗░██████╗░█████╗░░█████╗░███╗░░██╗
████╗░██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗██╔══██╗████╗░██║
██╔██╗██║█████╗░░░░░██║░░░╚█████╗░██║░░╚═╝███████║██╔██╗██║
██║╚████║██╔══╝░░░░░██║░░░░╚═══██╗██║░░██╗██╔══██║██║╚████║
██║░╚███║███████╗░░░██║░░░██████╔╝╚█████╔╝██║░░██║██║░╚███║
╚═╝░░╚══╝╚══════╝░░░╚═╝░░░╚═════╝░░╚════╝░╚═╝░░╚═╝╚═╝░░╚══╝
""")
        print("netscan by Eugenio Pastoral\n")
        print("netscan is a TCP port scanning and ping sweep tool that uses Scapy to craft and send out appropriate packets. It can detect open, closed, filtered, and unfiltered ports. It can also detect live hosts.\n")
        print("NOTE: In order to ensure that the program is going to work correctly, please install the latest version of Scapy.")
    else:
        ip = args.H
        type = None
        end = None
        try:
            if args.t:
                if type != None:
                    raise Exception()
                type = 1
            if args.s:
                if type != None:
                    raise Exception()
                type = 2
            if args.x:
                if type != None:
                    raise Exception()
                type = 3
            if args.f:
                if type != None:
                    raise Exception()
                type = 4
            if args.n:
                if type != None:
                    raise Exception()
                type = 5
            if args.a:
                if type != None:
                    raise Exception()
                type = 6
            if args.ALL:
                if type != None:
                    raise Exception()
                type = 0
                end = 7
            if args.i:
                type = 0
                if type != None and end != None:
                    raise Exception()
        except Exception as e:
            print('\nInvalid argument combination supplied. Try again.')
            parser.print_help()
            exit(0)
        port = args.p

        if type == None or ip == None:
            print('\nInsufficient arguments supplied. Try again.')
            parser.print_help()
            exit(0)

        # Check args present and set variables
        if not args.i:
            if (port == None):
                print('\nPlease specify a valid port to perform a port scan.')
                parser.print_help()
                exit(0)

        if not ipv4.validate_ip(ip):
            print('\nIP address is missing or invalid. Please try again.')
            parser.print_help()
            exit(0)

        if args.i:
            if args.c == None:
                scanner.ping(ip, 10)
            else:
                scanner.ping(ip, args.c)

        if args.ALL:
            for type in range (1, 7):
                scanner.portscan(ip, port, type)
                print('\n=============================================')
        elif args.ALL != True and args.i != True:
                scanner.portscan(ip, port, type)

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
        t.join()
    except KeyboardInterrupt as e:
        sys.exit(0)
