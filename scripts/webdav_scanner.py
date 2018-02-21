#!/usr/bin/env python2.7

# Author: m8r0wn
# Script: webdav_scanner.py

# Disclaimer:
# This tool was designed to be used only with proper
# consent. Use at your own risk.

import sys
import socket
from threading import Thread
from resources.pts import list_targets, arg_parser

def banner():
    print """
              webdav_scanner.py
      -----------------------------------
Check if webdav enabled via HTTP response codes

Options:
    -t          Number of threads (default: 4)
    -p          Port (default: 80)
    -v          verbose output

Usage:
    python webdav_scanner.py 10.0.0.0/24
    python webdav_scanner.py -v 192.168.2.1-20
    """
    sys.exit(0)

def main():
    # Help banner
    if "-h" in sys.argv or len(sys.argv) == 1: banner()

    targets = list_targets(sys.argv[-1])
    v = arg_parser(flag='-v', type='bool', default=False)
    max_threads = arg_parser(flag='-t', type='int', default=4)
    port = arg_parser(flag='-p', type='int', default=80)

    print "\n[*] Starting WebDav Scan\n", "-"*29
    scan_count = 0

    while scan_count != len(targets):
        threads = []
        for z in range(0, max_threads):
            if scan_count != len(targets):
                x = Thread(target=scan, args=(targets[scan_count], port, v,))
                threads.append(x)
                x.daemon = True
                x.start()
                scan_count += 1
        for t in threads:
            t.join(1)
    print "\n[!] Scan Complete\n\n"
    sys.exit(0)

def scan(t, port, v):
    # Setup Socket Connection
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)

    # HTTP Request Header
    data = 'PROPFIND / HTTP/1.1\n'
    data += 'Host: %s\n' % (t)
    data += 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.131 Safari/537.36\n'
    data += 'Content-Type: application/xml\n'
    data += 'Content-Length: 0\n\n'

    try:
        sock.connect((t, port))
        sock.send(data)
        resp = sock.recv(2014)

        sys.stdout.flush()
        x = resp.splitlines()[0]
        # check for 207 response code
        if "207" in x:
            srv_count = 0
            for y in resp.splitlines():
                if srv_count == 1: break
                if 'Server:' in y:
                    sys.stdout.write("[+] WebDav Enabled: %s (Code: %s %s)\n" % (t, x.split(" ")[1], y))
                    srv_count += 1
            if srv_count != 1:
                print sys.stdout.write("[+] WebDav Enabled: %s (Code: %s Server: N/A)\n" % (t, x.split(" ")[1]))
        else:
            sys.stdout.write("[-] WebDav Disabled: %s (Code: %s)\n" % (t, x.split(" ")[1]))
        sock.close()
    except KeyboardInterrupt:
        sock.close()
        print "\n[!] Key Event Detected...\n\n"
        sys.exit(0)
    except Exception as e:
        if v:
            sys.stdout.write("[-] WebDav Disabled: %s (%s)\n" % (t, e))
        sock.close()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print "\n[!] Key Event Detected...\n\n"
        sys.exit(0)