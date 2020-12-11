import socket, re

try:
    from scapy.all import *
except ImportError:
    print("Scapy library for Python is not installed on your system. Run 'pip install --pre scapy[basic]' to install the library.")
    print("For more information, visit https://scapy.readthedocs.io/en/latest/installation.html to isntall Scapy.")
    exit(0)

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
