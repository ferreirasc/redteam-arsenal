#!/usr/bin/python

# Um simples port-scan em python (TCP_Connections)
# Leonardo Ferreira - leoferreirafx@gmail.com

import sys
import socket
import subprocess

ports_open = []

if(len(sys.argv) != 3):
	print "---------------------------------------------------------"
	print "Usage: scanport.py <HOST> <Start-End>"
	print "Example: scanport.py www.inf.ufes.br 1-100"
	print "---------------------------------------------------------"
else:
	ip = sys.argv[1]
	ip = socket.gethostbyname(ip)
	port_range = sys.argv[2]
	port_range = port_range.split('-')

	start = int(port_range[0])
	end = int(port_range[1])

	if(start < 0 or start>65535 or end < 0 or end > 65535 or start>=end):
		print "Invalid range of ports."
		sys.exit()
		
	for i in range(start,end+1):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(1)
		if (s.connect_ex((ip, i))==0):
			print("Port %d is open." %i)
			ports_open.append(i)
		else:
			print("Port %d is closed." %i)
	
	print "---------------------------------------------------------"
	print "Scanning Completed."
	if(len(ports_open)>0):
		print "Open ports:"
		for i in range(len(ports_open)):
			print("Port %d:	Open" % ports_open[i])
	else:
		print "All ports are closed."
	print "---------------------------------------------------------"
