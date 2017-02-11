#Implementation of a ring network topology based in chord protocol

import socket
import sys
from random import randint
from struct import *
from time import *

def int2ip(addr):
    return socket.inet_ntoa(pack("!I", addr))

def ip2int(addr):
    return unpack("!I", socket.inet_aton(addr))[0]

def send_JOIN(cod_message, UDP_IP_REDE, MY_IP_int):
	sock.sendto(pack('! c I I',cod_message,IDENTIFIER, MY_IP_int), (UDP_IP_REDE, UDP_PORT))

def send_JOIN_R(cod_message, error, prox, IP_prox, ant, IP_ant, IP_dest):
	sock.sendto(pack('! c c I I I I',cod_message, error, prox, IP_prox, ant, IP_ant), (IP_dest, UDP_PORT))

def send_ack_join(cod_message, error, id_ant, ip_new, IP_dest):
	sock.sendto(pack('! c c I I',cod_message, error, id_ant, ip_new), (IP_dest, UDP_PORT))

def send_update(cod_message, id_orig, id_suc, ip_new, IP_dest):
	sock.sendto(pack('! c I I I',cod_message, id_orig, id_suc, ip_new), (IP_dest, UDP_PORT))

def send_update_ack(cod_message, error, identifier, IP_dest):
	sock.sendto(pack('! c c I',cod_message, error, identifier), (IP_dest, UDP_PORT))

def send_leave_message(cod_message, id_orig, id_suc, IP_suc, id_ant, IP_ant, IP_dest):
	sock.sendto(pack('! c I I I I I',cod_message, id_orig, id_suc, IP_suc, id_ant, IP_ant), (IP_dest, UDP_PORT))

def send_leave_ack(cod_message, id_orig, IP_dest):
	sock.sendto(pack('! c I',cod_message,IDENTIFIER), (IP_dest, UDP_PORT))

UDP_PORT = 12345
MY_IP = raw_input("Entre com o IP desta maquina: ")
MY_IP_int = ip2int(MY_IP)
IDENTIFIER = randint(0,10000)
print "MY IDENTIFIER: %d" %(IDENTIFIER)
ant = -1
prox = -1

while True:
	print "[+] Choose the operation for this node:"
	print "1 - Start new network\n2 - Join\n3 - Leave network"
	operation = int(raw_input())
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

	try:
		sock.bind((MY_IP, UDP_PORT))
	except socket.error as msg:
    		print 'Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    		sys.exit()

	if(operation == 1 and ant == -1):
		print "[-] Create new network."
		ant = prox = IDENTIFIER
		IP_prox = MY_IP
		IP_ant = MY_IP
		print "[-] Successor node: %s, Predecessor: %s" %(IDENTIFIER, IDENTIFIER)
	elif(operation == 2):
		UDP_IP_REDE = raw_input("[-] Enter with any IP of the known network: ");
		print "[-] Sending join message for %s" %(UDP_IP_REDE)
		send_JOIN(chr(1), UDP_IP_REDE, MY_IP_int); #Envia o JOIN para um host conhecido na rede.
		join_R_data = ""
		print "[-] Wait for join response..."
		while (not join_R_data):
			join_R_data, addr = sock.recvfrom(1024)
		print "[-] Join response received."
		join_R_data = unpack('! c c I I I I', join_R_data)
		print join_R_data
		if(ord(join_R_data[1]) == 1):
			ant = join_R_data[4]
			prox = join_R_data[2]
			IP_prox = int2ip(join_R_data[3])
			IP_ant = int2ip(join_R_data[5])
			print "[-] Sending confirmation message for join to " + str(addr)
			send_ack_join(chr(102), chr(1), IDENTIFIER, ip2int(MY_IP), addr[0])
			sleep(0.25)
			print "[-] Sending update message to %s" %(IP_ant)
			send_update(chr(3),IDENTIFIER, IDENTIFIER, ip2int(MY_IP), IP_ant)
			update_R_data = ""
			print "[-] Wait for update response..."
			while (not update_R_data):
				update_R_data, addr = sock.recvfrom(1024)
			print "[-] Update response received."
		elif(ord(join_R_data[1]) == 0):
			print "[-] Error!"
		print "Predecessor ID: %d, Successor ID: %d" %(ant, prox)
	elif(operation == 1 and ant != -1):
		print "[-] Network already exists."
	elif(operation == 3):
		if(ant!=-1):
			print "[-] Sending leave message for the successor node and predecessor node"
			send_leave_message(chr(2), IDENTIFIER, prox, ip2int(IP_prox), ant, ip2int(IP_ant), IP_prox)
			leave_R_data = ""
			while (not leave_R_data):
				leave_R_data, addr = sock.recvfrom(1024)
			print "[-] Leave response received from successor " + str(addr)
			prox_anterior = prox
			prox = -1
			send_leave_message(chr(2), IDENTIFIER, prox_anterior, ip2int(IP_prox), ant, ip2int(IP_ant), IP_ant)
			leave_R_data = ""
			while (not leave_R_data):
				leave_R_data, addr = sock.recvfrom(1024)
			print "[-] Leave response received from predecessor " + str(addr)
			ant = -1
			print "Predecessor ID: %d, Sucessor ID: %d" %(ant, prox)
			continue
		else:
			print "[-] This node does not participate in any network."
			continue

	while 1:
		try:
			print "Predecessor ID: %d, Sucessor ID: %d" %(ant, prox)
			print "[-] %s listen to requests..." %(MY_IP)
			data, addr = sock.recvfrom(1024)
			cod_message = unpack('! c', data[0])[0]
			print "[-] Request received."

			if(ord(cod_message) == 1):
				unpkddata = data
				data = unpack('! c I I', data)
				new_id = data[1]
				IP_dest = int2ip(data[2])
				print "[-] Join message from %d with IP adress %s" %(new_id,addr[0])
				if(ant == prox and ant != -1 and MY_IP == IP_prox): #so um elemento na rede
					print "[-] Reply message for ",(IP_dest)
                    #print "entrou1"
					send_JOIN_R(chr(101), chr(1), IDENTIFIER, ip2int(MY_IP), ant, ip2int(IP_ant), IP_dest)
					print "Predecessor ID: %d, Successor ID: %d" %(ant, prox)
				elif(ant == prox and ant == -1):
					send_JOIN_R(chr(203), chr(0), 0, 0, 0, 0, IP_dest)
				elif(new_id > IDENTIFIER and new_id > ant and IDENTIFIER < ant):
					print "[-] Reply message for %s" %(IP_dest)
					send_JOIN_R(chr(101), chr(1), IDENTIFIER, ip2int(MY_IP), ant, ip2int(IP_ant), IP_dest)
					print "Predecessor ID: %d, Successor ID: %d" %(ant, prox)
				elif(new_id < IDENTIFIER and new_id < ant and IDENTIFIER < ant):
					print "[-] Reply message for %s" %(IP_dest)
					send_JOIN_R(chr(101), chr(1), IDENTIFIER, ip2int(MY_IP), ant, ip2int(IP_ant), IP_dest)
					print "Predecessor ID: %d, Successor ID: %d" %(ant, prox)
				elif(new_id < IDENTIFIER and new_id > ant):
					print "[-] Reply message for %s" %(IP_dest)
					send_JOIN_R(chr(101), chr(1), IDENTIFIER, ip2int(MY_IP), ant, ip2int(IP_ant), IP_dest)
					print "Predecessor ID: %d, Successor ID: %d" %(ant, prox)
				else:
					print "Forwarding join for %s" %(IP_prox)
					sock.sendto(unpkddata, (IP_prox, UDP_PORT))

			elif(ord(cod_message) == 102):
				data = unpack('! c c I I', data)
				print "[-] Ack message of the join from " + str(addr)
				ant = data[2]
				IP_ant = int2ip(data[3])
				print "Predecessor ID: %d, Successor ID: %d" %(ant, prox)
			elif(ord(cod_message) == 3):
				data = unpack('! c I I I', data)
				print "[-] Update message from " + str(addr)
				prox = data[2]
				IP_prox = int2ip(data[3])
				print "Predecessor ID: %d, Sucessor ID: %d, IP_PROX = %s, IP_ANT = %s" %(ant, prox, IP_prox, IP_ant)
				send_update_ack(chr(203), chr(1), IDENTIFIER, addr[0])
			elif(ord(cod_message) == 2):
				data = unpack('! c I I I I I', data)
				print "[-] Sending ack message of the leave from " + str(addr)
				if(prox == data[1]):
					prox = data[2]
					IP_prox = int2ip(data[3])
				if(ant == data[1]):
					ant = data[4]
					IP_ant = int2ip(data[5])
				send_leave_ack(chr(201), IDENTIFIER, addr[0])
		except (KeyboardInterrupt, SystemExit):
			break
