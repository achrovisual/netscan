#!/usr/bin/env python3

import argparse, time, port_scan

src_ip = get_if_addr(conf.iface)

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
        response = port_scan.probe_port(ip, int(port), flags, flag, type)
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
