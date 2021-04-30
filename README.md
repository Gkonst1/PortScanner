# PortScanner

A basic CLI port scanner, which checks for open ports in a IPv4 address.

#### The coloured text is available only on UNIX systems (ref: https://stackoverflow.com/a/287944).
----------------------------------------------------------------------------------------------------

### Usage:
	- To scan a range of ports: `python3 portScanner.py <IP> <from_port[OPTIONAL]> <to_port[OPTIONAL]>`
	- To scan only one port   : `python3 portScanner.py <IP> <port>`
	- To scan all 65535 ports : `python3 portScanner.py <IP>`

----------------------------------------------------------------------------------------------------

### Arguments:
	- IP       : The IPv4 address of the target.
	- from_port: The starting port number. [OPTIONAL]
	- to_port  : The final port number. [OPTIONAL]

----------------------------------------------------------------------------------------------------

### TODO:
	- Add support for stealth scan(SYN -> ACK -> RST)
	- Add support for IPv6 addresses
	- Add more scan types to minimize the false negatives.

----------------------------------------------------------------------------------------------------

Created by © Gkonst
