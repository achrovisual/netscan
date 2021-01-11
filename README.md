# netscan
Simple CLI implementation of various TCP port scans using Python and Scapy.

## Dependencies
* Scapy

## ICMP Scanning
The program can check if a host is alive by the specified IP address. The syntax for performing a ICMP scan is as follows:
```
sudo ptyhon3 netscan.py -i [host] -c [number of packets]
```
## TCP Port Scanning
The program can perform various TCP port scanning techniques to see whether the port is open or not, or if there is a firewall in place. The syntax for performing a ICMP scan is as follows:
```
sudo ptyhon3 netscan.py -p [port] -[scaning mode] [host]
```
## Arguments
These are the following arguments the program can use.
### Required Arguments
| Argument  | Description |
| ------------- | ------------- |
| H  | Target Host IP or URL  |
| -p  | Target Port  |
### TCP Port Scanning Arguments
| Argument  | Description |
| ------------- | ------------- |
| -t  | Perform TCP Connect Scan  |
| -s  | Perform TCP SYN Scan  |
| -x  | Perform TCP XMAS Scan  |
| -f  | Perform TCP FIN Scan  |
| -n  | Perform TCP NULL Scan  |
| -a  | Perform TCP ACK Scan  |
| -ALL  | Perform ALL TCP Port Scans  |
### ICMP Port Scanning Arguments
| Argument  | Description |
| ------------- | ------------- |
| -i  | Perform ICMP Scan  |
| -c  | Number of ICMP ECHO Requests  |
### Optional Arguments
| Argument  | Description |
| ------------- | ------------- |
| -T  | Show time spent to compelete the scan  |
| -v  | Show program description  |
