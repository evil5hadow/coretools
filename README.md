# Pentest-Scripts
This is a collection of scripts I wrote or had the idea to write during penetration testing. Some have been modified and turned into full blown tools.

To get started, download the repository and run the setup.sh script to verify all required packages are installed.

## Getting Started
In the Linux terminal type:
* git clone https://github.com/m8r0wn/pentest-scripts
* sudo chmod +x pentest-scripts/setup.sh
* sudo ./pentest-scripts/setup.sh

## Scripts
* `dns_enum.py` - DNS subdomain enumeration and options to perform zone transfer
* `dns_lookup.py` - DNS lookup and reverse lookups
* `eyesee.sh` - Port scans a target network with nmap and takes snapshot of service with Eye Witness
* `eyesee_robots.sh` - Takes a snapshot of all pages in a site's robots.txt with Eye Witness
* `get_server.py` - Returns the HTTP response 'Server' header
* `smb_login.py` - SMB brute force tool
* `ssh_login.py` - SSH brute force tool. Once authenticated can execute multiple commands on multiple hosts
* `webdav_scanner.py` - Checks if webdav is enabled