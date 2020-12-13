# Author: Eugenio Pastoral
# Course: Advanced and Offensive Security

import port_scan, sys

# This function will initiate TCP port scans. It will get the mode to be used based on the arguments used. It takes in the target IP address, target port, and scan type flag as the parameters.

def portscan(ip, port, type):
    # Get the type and set the appropriate flags to be set in the packet.
    flag, flags = parse_type(ip, port, type)

    # Check if the target host is alive.
    if port_scan.is_up(ip):
        # Send a TCP packet based on the flags from the previous line. The return value will determine if it's open, closed, filtered, unfiltered.
        response = port_scan.probe_port(ip, int(port), flags, flag, type)

        # If the return value is 1, it is open.
        if response == 1:
            openp = port
            filterdp = ''

        # If the return value is 2, it is filtered.
        elif response == 2:
            filterdp = port
            openp = ''

        # Otherwise, it closed or unfiltered.
        else:
            filterdp, openp = '', ''

        # If the scanning mode is TCP Connect Scan, print the following messages.
        if type == 1:
            if response == 1:
                print('\n' + port + " is open.")
            else:
                print('\n' + port + " is closed.")

        # If the scanning mode is TCP SYN Scan, TCP XMAS Scan, TCP FIN Scan, or TCP NULL Scan, print the following messages.
        if type == 2 or type == 3 or type == 4 or type == 5:
            if openp != '':
                print('\n' + openp + " is possibly open or filtered.")
            if filterdp != '':
                print('\n' + filterdp + " is filtered.")
            if (openp == '') and (filterdp == ''):
                print('\n' + port + " is closed.")

        # If the scanning mode is TCP ACK Scan, print the following messages.
        if type == 6:
            if openp != '':
                print('\n' + openp + " is filtered by stateful firewall.")
            if filterdp != '':
                print('\n' + filterdp + " is filtered by stateful firewall.")
            if (openp == '') and (filterdp == ''):
                print('\n' + port + " is not filtered.")

    # Otherwise, the target host is down.
    else:
        print("Host is down.")



# This function will set the appropriate flags based on the scanning mode specified. It takes in the target IP address, target port, and scan type flag as the parameters.

def parse_type(ip, port, type):
    # If the scanning mode is TCP Connect Scan, set the appropriate flags.
    if type == 1:
        print('\nPerforming TCP Connect Scan on ' + ip + ':' + port + '.\n')
        return 0x14, 'S'

    # If the scanning mode is TCP SYN Scan, set the appropriate flags.
    elif type == 2:
        print('\nPerforming TCP SYN Scan on ' + ip + ':' + port + '.\n')
        return 0x14, 'S'

    # If the scanning mode is TCP XMAS Scan, set the appropriate flags.
    elif type == 3:
        print('\nPerforming TCP XMAS Scan on ' + ip + ':' + port + '.\n')
        return 0x14, 'FPU'

    # If the scanning mode is TCP FIN Scan, set the appropriate flags.
    elif type == 4:
        print('\nPerforming TCP FIN Scan on ' + ip + ':' + port + '.\n')
        return 0x14, 'F'

    # If the scanning mode is TCP NULL Scan, set the appropriate flags.
    elif type == 5:
        print('\nPerforming TCP NULL Scan on ' + ip + ':' + port + '.\n')
        return 0x14, ''

    # If the scanning mode is TCP ACK Scan, set the appropriate flags.
    elif type == 6:
        print('\nPerforming TCP ACK Scan on ' + ip + ':' + port + '.\n')
        return 0x4, 'A'



# This function will initiate a Ping Sweep. It will send out n ICMP ECHO requests to the target host. It takes in the target IP address and the number of packets to be sent.

def ping(ip, n):
    print('\nPerforming Ping Sweep on ' + ip + '.\n')

    # Send n ICMP ECHO requests.
    for i in range(n):
        if port_scan.is_up(ip):
            print('[' + (i + 1) + ']' + ip + ' is alive.')
