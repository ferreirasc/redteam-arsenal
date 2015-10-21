#!/bin/bash

USER=ggp
PASSWORD=blabla
HOME=/home/stack
CONFIG="install_openstack_server_controller_v*.sh"
LIB="../functions.sh"
CONFIGS="configs"



	echo "Copy to host 192.168.0.$IP"
	#~ ssh-keygen -f "/home/user/.ssh/known_hosts" -R 192.168.43.$IP

	FILES=" cliente.py
	      "
	scp -r $FILES $USER@192.168.0.183:/home/ggp
	scp -r $FILES stack@192.168.0.114:/home/stack
	#~ ssh $USER@192.168.43.$IP "echo "$PASSWORD" | sudo -S ./$CONFIG"
