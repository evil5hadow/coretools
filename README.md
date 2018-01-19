# Pentest-Scripts
This is a collection of scripts written during penetration testing. Some have been modified and turned into full blown tools. For more information visit: [https://m8r0wn-cyber.blogspot.com](https://m8r0wn-cyber.blogspot.com).

To get started, download the repository and run the setup.sh script to verify all required packages are installed.

## Getting Started
In the Linux terminal type:
* git clone https://github.com/m8r0wn/pentest-scripts
* sudo chmod +x pentest-scripts/setup.sh
* sudo ./pentest-scripts/setup.sh

## Scripts
* `dns_enum.py` - DNS subdomain enumeration and options to perform zone transfer
* `dns_lookup.py` - DNS lookup and reverse lookups
* `eyesee.sh` - port scans a target network with nmap and takes snapshot of service with Eye Witness
* `eyesee_robots.sh` - Takes a snapshot of all pages in a site's robots.txt
* `get_server.py` - Returns the HTTP response 'Server' header
* `smb_login.py` - SMB brute force tools
* `ssh_login.py` - SSH brute force tool. Once authenticated can execute multiple commands on multiple hosts
* `webdav_scanner.py` - Checks if webdav enabled