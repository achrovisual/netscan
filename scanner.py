import port_scan, sys

def portscan(ip, port, type):
    flag, flags = parse_type(ip, port, type)
    if port_scan.is_up(ip):
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



def parse_type(ip, port, type):
    if type == 1:
        print('\nPerforming TCP Connect Scan on ' + ip + ':' + port + '.\n')
        return 0x14, 'S'

    elif type == 2:
        print('\nPerforming TCP SYN Scan on ' + ip + ':' + port + '.\n')
        return 0x14, 'S'

    elif type == 3:
        print('\nPerforming TCP XMAS Scan on ' + ip + ':' + port + '.\n')
        return 0x14, 'FPU'

    elif type == 4:
        print('\nPerforming TCP FIN Scan on ' + ip + ':' + port + '.\n')
        return 0x14, 'F'

    elif type == 5:
        print('\nPerforming TCP NULL Scan on ' + ip + ':' + port + '.\n')
        return 0x14, ''

    elif type == 6:
        print('\nPerforming TCP ACK Scan on ' + ip + ':' + port + '.\n')
        return 0x4, 'A'

def ping(ip, n):
    print('\nPerforming Ping Sweep on ' + ip + '.\n')
    for i in range(n):
        if port_scan.is_up(ip):
            print(ip + ' is alive.')
