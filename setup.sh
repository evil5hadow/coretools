#!/usr/bin/env bash

# Author: m8r0wn
# Script: setup.sh

# Description:
# Coretools setup verifies all required packages
# are installed on the system.

#Check if Script run as root
if [[ $(id -u) != 0 ]]; then
	echo -e "\n[!] Setup script needs to run as root\n\n"
	exit 0
fi

echo -e "\n[*] Starting coretools setup"
echo -e "[*] Checking for Python 2.7"
if [[ $(python2.7 -V 2>&1) == *"not found"* ]]
then
    echo -e "[*] Installing Python 2.7"
    apt-get install python2.7 -y
else
    echo "[+] Python 2.7 installed"
fi

echo -e "[*] Checking for non-standard libraries"
if [[ $(python2.7 -c "import BeautifulSoup" 2>&1) == *"No module"* ]]
then
    echo -e "[*] Installing python-beautifulsoup"
    apt-get install python-beautifulsoup -y
else
    echo "[+] BeautifulSoup installed"
fi

if [[ $(python2.7 -c "import dns.resolver" 2>&1) == *"No module"* ]]
then
    echo -e "[*] Installing python-dnspython"
    apt-get install python-dnspython -y
else
    echo "[+] dnspython installed"
fi

if [[ $(python2.7 -c "import paramiko" 2>&1) == *"No module"* ]]
then
    echo -e "[*] Installing python-paramiko"
    apt-get install python-paramiko -y
else
    echo "[+] Paramiko installed"
fi

if [[ $(python2.7 -c "from smb.SMBConnection import SMBConnection" 2>&1) == *"No module"* ]]
then
    echo -e "[*] Installing python-smb"
    apt-get install python-smb -y
else
    echo "[+] pysmb installed"
fi

echo -e "\n[*] Coretools setup complete\n\n"
