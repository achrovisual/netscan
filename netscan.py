#!/usr/bin/env python3

import socket, re, argparse, time
from scapy.all import *

src_ip = get_if_addr(conf.iface)

def is_up(ip):
    icmp = IP(dst=ip)/ICMP()
    resp = sr1(icmp, timeout=10, verbose = 0)
    if resp == None:
        return False
    else:
        return True

def probe_port(ip, port, flags, flag, scan_type, result = 1):
    src_port = RandShort()
    try:
        p = IP(dst=ip)/TCP(sport=src_port, dport=port, flags=flags)

        if flags == 'S':
            print(src_ip + ' > SYN > ' + ip)
        elif flags == 'FPU':
            print(src_ip + ' > FIN, PSH, URG > ' + ip)
        elif flags == 'F':
            print(src_ip + ' > FIN > ' + ip)
        elif flags == 'A':
            print(src_ip + ' > ACK > ' + ip)
        elif flags == '':
            print(src_ip + ' > NULL > ' + ip)

        resp = sr1(p, timeout = 2, verbose = 0) # Send packet
        rcv_ip = resp.getlayer(IP).src

        if str(type(resp)) == "<class 'NoneType'>":
            result = 1
        elif resp.haslayer(TCP):
            if resp.getlayer(TCP).flags == 0x12:
                print(src_ip + ' < SYN, ACK < ' + ip)
                if scan_type == 2:
                    send_rst = sr(IP(dst=ip)/TCP(sport=src_port, dport=port, flags='R'), timeout = 2, verbose = 0)
                    print(src_ip + ' > RST > ' + ip)
                elif scan_type == 1:
                    send_ack = send(IP(dst=ip)/TCP(sport=src_port, dport=port, flags='A', ack = resp.seq + 1, seq = resp.ack + 1), verbose = 0)
                    print(src_ip + ' > ACK > ' + ip)
                result = 1
            elif resp.getlayer(TCP).flags == flag:
                if flag == 0x14:
                    print(src_ip + ' < RST, ACK < ' + ip)
                elif flag == 0x4:
                    print(src_ip + ' < RST < ' + ip)
                result = 0
            elif (int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                result = 2
    except AttributeError as e:
        print('No response')
        pass
    except ValueError as e:
        print('No response')
        result = 0
    except Exception as e:
        print(e)
        pass
    return result

def main():
    start = time.time()
    # Arg Parsing
    parser = argparse.ArgumentParser(description='', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("H",  help = "Target Host IP or URL")
    parser.add_argument("-p", "--p", help = "Targeted Port(s), comma delimited", required = "True")
    parser.add_argument("-t", "--t", type = int, help = "Port Scan Type. The following port scan types can be used:\n1) TCP Connect Scan\n2) TCP SYN Scan\n3) XMAS Scan\n4) FIN Scan\n5) Null Scan\n6) TCP ACK Scan", required = "True")
    args = parser.parse_args()
    ip = args.H
    type = args.t
    port = args.p
    # Check args present and set variables
    if (ip == None) | (port == None):
        parser.print_help()
        exit(0)

    if type == 1:
        print('\nPerforming TCP Connect Scan on ' + ip + ':' + port + '.\n')
        flags = 'S'
        flag = '0x14'
    elif type == 2:
        print('\nPerforming TCP SYN Scan on ' + ip + ':' + port + '.\n')
        flags = 'S'
        flag = 0x14
    elif type == 3:
        print('\nPerforming TCP XMAS Scan on ' + ip + ':' + port + '.\n')
        flags = 'FPU'
        flag = 0x14
    elif type == 4:
        print('\nPerforming TCP FIN Scan on ' + ip + ':' + port + '.\n')
        flags = 'F'
        flag = 0x14
    elif type == 5:
        print('\nPerforming TCP NULL Scan on ' + ip + ':' + port + '.\n')
        flags = ''
        flag = 0x14
    elif type == 6:
        print('\nPerforming TCP ACK Scan on ' + ip + ':' + port + '.\n')
        flags = 'A'
        flag = 0x4

    if is_up(ip):
        response = probe_port(ip, int(port), flags, flag, type)
        if response == 1:
            openp = port
            filterdp = ''
        elif response == 2:
            filterdp = port
            openp = ''
        else:
            filterdp, openp = '', ''

        if type == 1:
            if response == 1:
                print('\n' + port + " is open.")
            else:
                print('\n' + port + " is closed.")

        if type == 2 or type == 3 or type == 4 or type == 5:
            if openp != '':
                print('\n' + openp + " is possibly open or filtered.")
            if filterdp != '':
                print('\n' + filterdp + " is filtered.")
            if (openp == '') and (filterdp == ''):
                print('\n' + port + " is closed.")
        if type == 6:
            if openp != '':
                print('\n' + openp + " is filtered by stateful firewall.")
            if filterdp != '':
                print('\n' + filterdp + " is filtered by stateful firewall.")
            if (openp == '') and (filterdp == ''):
                print('\n' + port + " is not filtered.")
    else:
        print("Host is down.")

    end = time.time()

    print('\nCompleted scan in ' + str(round((end - start), 4)) + 's.')
if __name__ == '__main__':
    main()
