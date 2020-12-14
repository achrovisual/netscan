# Author: Eugenio Pastoral
# Course: Advanced and Offensive Security

import socket, re, sys

# Check if Scapy is installed. If not, prompt the user to install the library.
try:
    from scapy.all import *

except ImportError:
    print("Scapy library for Python is not installed on your system. Run 'pip install --pre scapy[basic]' to install the library.")
    print("For more information, visit https://scapy.readthedocs.io/en/latest/installation.html to isntall Scapy.")
    exit(0)



# Get the IP address of the main interface of the source host.
src_ip = get_if_addr(conf.iface)



# This function will send out an ICMP ECHO request to the target host. It takes in the target IP address as a parameter.

def is_up(ip):
    # Craft the ICMP packet.
    icmp = IP(dst=ip)/ICMP()

    # Send out the packet and wait for the response.
    resp = sr1(icmp, timeout = 2, verbose = 0)

    # If there's no response, return false.
    if resp == None:
        return False

    # Otherwise, return true.
    else:
        return True



# This function will probe a given port. The scanning mode will be dependent on the type specified. Each mode will have different flags set for their respective packets. It takes in the target IP address, target port, flags for the TCP packet, flag for the response packet, the scanning mode, and a resultant variable.

def probe_port(ip, port, flags, flag, scan_type, print_flag, result = 1):
    # Get a random source port.
    src_port = RandShort()

    try:
        # Craft the TCP packet and set the appropriate flags based on the scanning mode specified.
        p = IP(dst=ip)/TCP(sport=src_port, dport=port, flags=flags)

        if print_flag:
            # If the packet being sent has the SYN flag, print this message.
            if flags == 'S':
                print(src_ip + ' > SYN > ' + ip)

            # If the packet being sent has the FIN, PSH, and URG flags, print this message.
            elif flags == 'FPU':
                print(src_ip + ' > FIN, PSH, URG > ' + ip)

            # If the packet being sent has the FIN flag, print this message.
            elif flags == 'F':
                print(src_ip + ' > FIN > ' + ip)

            # If the packet being sent has the ACK flag, print this message.
            elif flags == 'A':
                print(src_ip + ' > ACK > ' + ip)

            # If the packet being sent has no flags, print this message.
            elif flags == '':
                print(src_ip + ' > NULL > ' + ip)

        # Send the packet to the target host and wait for a response.
        resp = sr1(p, timeout = 2, verbose = 0) # Send packet

        # Get the IP address of the sender from the response.
        rcv_ip = resp.getlayer(IP).src

        # Check if the packet has no type. If so, it's an open port.
        if str(type(resp)) == "<class 'NoneType'>":
            result = 1

        # If the response packet is a TCP packet, check the flags.
        elif resp.haslayer(TCP):
            # If it's a SYN, ACK packet, print the message and send an appropriate response.
            if resp.getlayer(TCP).flags == 0x12:
                if print_flag:
                    print(src_ip + ' < SYN, ACK < ' + ip)

                # If a TCP SYN Scan is being performed, send out an RST packet.
                if scan_type == 2:
                    send_rst = sr(IP(dst=ip)/TCP(sport=src_port, dport=port, flags='R'), timeout = 2, verbose = 0)
                    if print_flag:
                        print(src_ip + ' > RST > ' + ip)

                # If a TCP Connect Scan is being performed, send out an ACK, RST packet.
                elif scan_type == 1:
                    send_ack = send(IP(dst=ip)/TCP(sport=src_port, dport=port, flags='AR', ack = resp.seq + 1, seq = resp.ack + 1), verbose = 0)
                    if print_flag:
                        print(src_ip + ' > ACK, RST > ' + ip)

                # Return 1 since the port is open.
                result = 1

            # If it's a RST, ACK packet or RST packet, print the message and send an appropriate response.
            elif resp.getlayer(TCP).flags == flag:
                if print_flag:
                    # If a TCP Connect Scan is being performed, send out an RST packet.
                    if flag == 0x14 and scan_type == 1:
                        print(src_ip + ' < RST < ' + ip)

                    # If the flag is RST, ACK, send out an RST packet.
                    elif flag == 0x14:
                        print(src_ip + ' < RST < ' + ip)

                    # If the flag is RST, send out an RST packet.
                    elif flag == 0x4:
                        print(src_ip + ' < RST < ' + ip)

                # Return 1 since the port is closed.
                result = 0

            # If the response packet is an ICMP packet, check if it has the ICMP error flags.
            elif (int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                print('hello')
                # Return 2 since the port is filtered.
                result = 2

    # This will occur when a response has not been received.
    except AttributeError as e:
        if print_flag:
            print('No response')
        if scan_type == 1 or scan_type == 2:
            result = 2
        else:
            result == 1
        pass

    # This will occur when a response has not been received.
    except ValueError as e:
        if print_flag:
            print('No response')
        result = 2

    # Pass the other errors.
    except Exception as e:
        print(e)
        pass

    # Return the resultant variable.
    return result
