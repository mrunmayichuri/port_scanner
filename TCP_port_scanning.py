#!/usr/bin/env python
#Mrunmayi Churi
#Reference: http://null-byte.wonderhowto.com/how-to/build-stealth-port-scanner-with-scapy-and-python-0164779/

import sys
import logging
from scapy.all import *

try:
	print "TCP Port Scanner\n"	
	scan_IP = raw_input("Enter the IP address of the target: ")
	lower_port = raw_input("Enter the lower range of the port number: ")
	higher_port = raw_input("Enter the higher range of the port number: ")
	try:
		if int(lower_port) >= 0 and int(higher_port) >= 0 and  int(higher_port) >= int(lower_port) and int(higher_port) <= 65535:
			pass
		else:
			print "\nKindly enter valid port numbers"
			print "TCP Port Scanner is shutting down..."
			sys.exit(1)
	except Exception:
		print "\nKindly enter valid port numbers"
		print "TCP Port Scanner is shutting down..."
		sys.exit(1)
except KeyboardInterrupt:
	print "User interruption detected, TCP Port Scanner is shutting down..."
	sys.exit(1)	

ports = range(int(lower_port), int(higher_port)+1)
SYNACK = 0x12
RSTACK = 0x14

def check_IP_target(ip):
	conf.verb = 0			#This is to disable verbose output
	try:
		ping = sr1(IP(dst = ip)/ICMP())
		print "\nThe target is UP. Starting Scanner..."
	except Exception:
		print "\nUnable to resolve host"
		sys.exit(1)
def scanner(port):
	sourcep = RandShort()		#Obtaining a random source port
	conf.verb = 0
	SYN_ACK = sr1(IP(dst = scan_IP)/TCP(sport = sourcep, dport = port, flags = "S"),inter=0.5, retry=5, timeout=5)
        SYN_ACK.summary()
	packet_flags = SYN_ACK.getlayer(TCP).flags
	if packet_flags == SYNACK:
		return 1
	elif packet_flags == RSTACK:
		return 2
	else:
		return 3
	RST = IP(dst = scan_IP)/TCP(sport = sourcep, dport = port, flags = "R")
	send(RST)
	
check_IP_target(scan_IP)
for port in ports:
	current_state = scanner(port)
	if current_state == 1:
		print "Port no " + str(port) + " is Open"
	elif current_state == 2:
		print "Port no " + str(port) + " is Closed"
	elif current_state == 3:
		print "Port no " + str(port) + " is Filtered"
	else:
		print "The target host is down"


print "\nScanning finished"
	
