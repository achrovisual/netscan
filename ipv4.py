import socket

def validate_ip(ip):
    try:
        ip = socket.inet_aton(ip)
        return True
    except Exception as e:
        return False
