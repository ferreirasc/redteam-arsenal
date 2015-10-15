import socket
import sys
from struct import *

UDP_PORT = 12345
MY_IP = raw_input("Entre com o IP desta maquina: ")
IDENTIFIER = int(''.join(x for x in MY_IP.split('.')))
#print IDENTIFIER

def send_JOIN(UDP_IP_REDE):
	sock.sendto(pack('! c i','1',IDENTIFIER), (UDP_IP_REDE, UDP_PORT))
	

while True:
	print "[+] Choose the operation for this node:"
	print "1 - Start new network\n2 - Join\n3 - Leave network\n4 - Update network\n5 - Sair"
	operation = int(raw_input())
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.bind((MY_IP, UDP_PORT))

	if(operation == 1):
		print "[-] Create new network."
		print "[-] Successor node: %s, Predecessor: %s" %(IDENTIFIER, IDENTIFIER) 
		ant = prox = IDENTIFIER
	elif(operation == 2):
		UDP_IP_REDE = raw_input("[-] Enter with any IP of the known network: ");
		print "[-] Sending join message for %s" %(UDP_IP_REDE)
		send_JOIN(UDP_IP_REDE); #Envia o JOIN para um host conhecido na rede.
		join_R_data = ""
		print "[-] Wait for join response..."
		while (not join_R_data):
			join_R_data, addr = sock.recvfrom(1024)			
	elif(operation == 3):
		print "oi"
	elif(operation == 4): 
		print "oi3"
	elif(operation == 5):
		print "[-] %s listen to requests..." %(MY_IP)
		data, addr = sock.recvfrom(1024)
		print "[-] Request received."
		print unpack(data[0])
		print unpack(data), addr
