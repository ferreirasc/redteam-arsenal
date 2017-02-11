#Keyboard interrupt example
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("10.10.0.206", 12345))

while True:
	try:
		data, addr = sock.recvfrom(1024)
  	except (KeyboardInterrupt, SystemExit):
		break

print "Deixou de ouvir!"
