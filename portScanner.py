#!/usr/bin python3

"""
A basic CLI port scanner, which checks for open ports in a IPv4 address.

** The coloured text is available only on UNIX systems (ref: https://stackoverflow.com/a/287944).
----------------------------------------------------------------------------------------------------

Arguments:
	IP       : The IPv4 address of the target.
	from_port: The starting port number. [OPTIONAL]
	to_port  : The final port number. [OPTIONAL]

----------------------------------------------------------------------------------------------------

TODO:
	- Add support for stealth scan(SYN -> ACK -> RST)
	- Add more scan types to minimize the false negatives.

----------------------------------------------------------------------------------------------------

Created by © Gkonst
"""

import sys
import socket, errno
from datetime import datetime
import re #RegEx
import threading
import platform


starting_port    = None
ending_port      = None
ports_number     = 65535
open_ports       = 0
open_ports_array = []
separator        = ", " # We use it for the open ports print at the end of the program
host_os          = platform.system()
is_windows       = host_os == "Windows"

# The blocks' list of the splitted IPs to assign on each thread.
block_list = []

class Colors:
	none   = "" if is_windows else "\033[0m";
	red    = "" if is_windows else "\033[31m";
	green  = "" if is_windows else "\033[32m";
	yellow = "" if is_windows else "\033[33m";
	blue   = "" if is_windows else "\033[34m";
	purple = "" if is_windows else "\033[35m";
	cyan   = "" if is_windows else "\033[36m";

pattern = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

#########################
# FUNCTION DECLARATIONS #
#########################

"""Tests a given port, whether it's open or closed.

Creates a socket and sends a package to the given port to test if it's open or not.
"""
def createSocketAndCheckPort(port):
	global open_ports, open_ports_array

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	socket.setdefaulttimeout(1)
	result = s.connect_ex((target, port)) #returns an error indicator

	if result == 0:
		open_ports += 1
		open_ports_array.append(str(port))
		print(Colors.cyan + "Port" + Colors.green + ": " + str(port) + Colors.none + " is " + Colors.green + "UP")
	else:
		print(Colors.cyan + "Port" + Colors.yellow + ": " + Colors.cyan + str(port) + Colors.none + " is " + Colors.red + "DOWN")

	s.close()


"""Loop

Creates the loop, which checks a range of ports, whether they are open or closed.
"""
def checkPortsRange(thread, start_point, end_point):
	print(Colors.none + f"Thread {thread} executing...")
	print("")

	range_fix = 1 if thread != 5 else 2
	for port in range(start_point, end_point + range_fix):
		createSocketAndCheckPort(port)

	print("")
	print(Colors.none + f"Thread {thread} completed!")
	print("-" * 50)


"""Blocks creation

Splits the IPs into blocks of IPs

ref: https://stackoverflow.com/a/2130035
"""
def createIPsBlocks(range_of_ints, number_of_blocks):
    avg = len(range_of_ints) / float(number_of_blocks)
    last = 0.0

    while last < len(range_of_ints):
        block_list.append(range_of_ints[int(last):int(last + avg)])
        last += avg


############################
# CORE CODE OF THE PROGRAM #
############################


#Define the target
if len(sys.argv) >= 2:
	target = sys.argv[1] #Translate hostname to IPv4
else:
	print(Colors.red + "Invalid amount of arguments.")
	print(Colors.none + "Syntax: python3 portScanner.py <IP> <from_port[OPTIONAL]> <to_port[OPTIONAL]>")
	print(Colors.none + "For only one port check use syntax: python3 portScanner.py <IP> <port>")
	sys.exit()

# Checks if it is a valid IPv4 address
if not pattern.match(target):
	print(Colors.red + "Invalid" + Colors.none + " IPv4 address.")
	sys.exit()

if len(sys.argv) == 4:
	try:
		starting_port = int(sys.argv[2])
		ending_port = int(sys.argv[3])

		if starting_port > ending_port:
			starting_port, ending_port = ending_port, starting_port

		if not 1 <= starting_port <= ending_port <= ports_number:
			raise ValueError()
	except ValueError:
		print(Colors.red + "Invalid port numbers" + Colors.none)
		print("Port numbers should be integers between 1 and 65535")
		sys.exit()
elif len(sys.argv) == 3:
	port = int(sys.argv[2])
	createSocketAndCheckPort(port)
	sys.exit()

# Check what time the scan started
starting_time = datetime.now().replace(microsecond = 0)
open_ports = 0

#Add a pretty banner
print("-" * 50)
print("Scanning target: " + target)
print("Time started: " + str(starting_time))
print("-" * 50)


try:
	if starting_port is not None and ending_port is not None:
		if ending_port != starting_port:
			ports_number = ending_port - starting_port + 1

			if ports_number <= 10:
				checkPortsRange(thread= 1, start_point= starting_port, end_point= ending_port)
			else:
				createIPsBlocks(range(starting_port, ending_port), 5)
		else:
			# It is the case that the starting_port is the same number as the ending_port,
			# so we need to check just 1 port.
			createSocketAndCheckPort(starting_port)
			sys.exit()
	else:
		if ports_number <= 10:
			checkPortsRange(thread= 1, start_point= starting_port, end_point= ending_port)
		else:
			createIPsBlocks(range(1, ports_number), 5)

	# Create the threads
	threads = []

	for i in range(len(block_list)):
		t = threading.Thread(target= checkPortsRange(thread= i + 1, start_point= block_list[i][0], end_point= block_list[i][-1]))
		t.deamon = True
		threads.append(t)

	# Start the threads
	for thread in threads:
		thread.start()

	# Stop execution of current program until a thread is complete
	for thread in threads:
		thread.join()

except KeyboardInterrupt:
	print("\nExiting program.")
	sys.exit()

except socket.gaierror:
	print("Hostname cound not be resolved.")
	sys.exit()

except socket.error:
	print("Couldn't connect to server.")
	sys.exit()

# Checking the time again
finishing_time = datetime.now().replace(microsecond = 0)

# Calculates the difference of time, to see how long it took to run the script
total =  finishing_time - starting_time

# Printing the information to screen
print("Scanning Completed in:", total)
print("Found " + Colors.green + str(open_ports) + Colors.none +" port(s) open.")

if open_ports != 0:
	print("Open ports: " + Colors.green + separator.join(open_ports_array))
