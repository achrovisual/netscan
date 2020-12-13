# Author: Eugenio Pastoral
# Course: Advanced and Offensive Security

import socket

# This function will validate if an IPv4 address is valid or not. It takes in an IPv4 address as a parameter.

def validate_ip(ip):
    try:
        # Check if the given IP address is valid. This will throw an error if invalid.
        ip = socket.inet_aton(ip)

        # If valid, return true.
        return True

    except Exception as e:
        # If invalid, return false.
        return False
