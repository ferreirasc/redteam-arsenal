#!/usr/bin/python

import socket

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("172.16.1.5",21))

banner = s.recv(1024)

print "[+] Banner obtained:\n"+banner
while 1:
	cmd = raw_input()
	cmd.replace('\n','')
	if cmd:
		s.send(cmd + "\r\n")
		r = s.recv(4096)
		print r
