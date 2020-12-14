# Author: Eugenio Pastoral
# Course: Advanced and Offensive Security

import port_scan, sys

# This function will initiate TCP port scans. It will get the mode to be used based on the arguments used. It takes in the target IP address, target port, and scan type flag as the parameters.

def portscan(ip, port, type, print_flag):
    # Get the type and set the appropriate flags to be set in the packet.
    flag, flags = parse_type(ip, port, type, print_flag)

    # # Check if the target host is alive.
    # if port_scan.is_up(ip):
    # Send a TCP packet based on the flags from the previous line. The return value will determine if it's open, closed, filtered, unfiltered.
    response = port_scan.probe_port(ip, int(port), flags, flag, type, print_flag)

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
    if type == 1 or type == 2:
        if response == 1:
            if print_flag:
                print('\n' + port + " is open.")
            return 'O'
        elif response == 0:
            if print_flag:
                print('\n' + port + " is closed.")
            return 'C'
        else:
            t1_flag = 'F'
            if print_flag:
                print('\n' + port + " is filtered.")
            return 'F'

    # If the scanning mode is TCP SYN Scan, TCP XMAS Scan, TCP FIN Scan, or TCP NULL Scan, print the following messages.
    if type == 3 or type == 4 or type == 5:
        if openp != '':
            if print_flag:
                print('\n' + openp + " is possibly open or filtered.")
            return 'O|F'
        if filterdp != '':
            if print_flag:
                print('\n' + filterdp + " is filtered.")
            return 'F'
        if (openp == '') and (filterdp == ''):
            if print_flag:
                print('\n' + port + " is closed.")
            return 'C'

    # If the scanning mode is TCP ACK Scan, print the following messages.
    if type == 6:
        if openp != '':
            if print_flag:
                print('\n' + openp + " is filtered by stateful firewall.")
            return 'F'
        if filterdp != '':
            if print_flag:
                print('\n' + filterdp + " is filtered by stateful firewall.")
            return 'F'
        if (openp == '') and (filterdp == ''):
            if print_flag:
                print('\n' + port + " is not filtered.")
            return 'UF'
    #
    # # Otherwise, the target host is down.
    # else:
    #     print("Host is down.")



# This function will set the appropriate flags based on the scanning mode specified. It takes in the target IP address, target port, and scan type flag as the parameters.

def parse_type(ip, port, type, print_flag):
    # If the scanning mode is TCP Connect Scan, set the appropriate flags.
    if type == 1:
        if print_flag:
            print('\nPerforming TCP Connect Scan on ' + ip + ':' + port + '.\n')
        return 0x14, 'S'

    # If the scanning mode is TCP SYN Scan, set the appropriate flags.
    elif type == 2:
        if print_flag:
            print('\nPerforming TCP SYN Scan on ' + ip + ':' + port + '.\n')
        return 0x14, 'S'

    # If the scanning mode is TCP XMAS Scan, set the appropriate flags.
    elif type == 3:
        if print_flag:
            print('\nPerforming TCP XMAS Scan on ' + ip + ':' + port + '.\n')
        return 0x14, 'FPU'

    # If the scanning mode is TCP FIN Scan, set the appropriate flags.
    elif type == 4:
        if print_flag:
            print('\nPerforming TCP FIN Scan on ' + ip + ':' + port + '.\n')
        return 0x14, 'F'

    # If the scanning mode is TCP NULL Scan, set the appropriate flags.
    elif type == 5:
        if print_flag:
            print('\nPerforming TCP NULL Scan on ' + ip + ':' + port + '.\n')
        return 0x14, ''

    # If the scanning mode is TCP ACK Scan, set the appropriate flags.
    elif type == 6:
        if print_flag:
            print('\nPerforming TCP ACK Scan on ' + ip + ':' + port + '.\n')
        return 0x4, 'A'



# This function will initiate a Ping Sweep. It will send out n ICMP ECHO requests to the target host. It takes in the target IP address and the number of packets to be sent.

def ping(ip, n, print_flag):
    result = False
    if print_flag:
        print('\nPerforming Ping Sweep on ' + ip + '.\n')

    # Send n ICMP ECHO requests.
    for i in range(n):
        if port_scan.is_up(ip):
            if print_flag:
                print('[' + str(i + 1) + '] ' + ip + ' is alive.')
            result = True

    return result
