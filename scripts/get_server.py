#!/usr/bin/env python2.7

# Author: m8r0wn
# Script: get_server.py

# Disclaimer:
# This tool was designed to be used only with proper
# consent. Use at your own risk.

import urllib2
import ssl
import sys
from threading import Thread
from resources.pts import list_targets, arg_parser

def banner():
    print """
                    Get_Server.py
         -----------------------------------
This script will connect to the target machine(s) and return
the HTTP response "Server" header. Used for recon and
fingerprinting target machines.

Options:
    -m [http/https]         Default will be both http & https
    -v                      Verbose output (show failed attempts)
    -t                      Number of threads (default: 4)
    --dns                   Keep DNS name while running
                            (Default: will resolv dns names)

Usage:
    python get_server.py -m http scope.txt
    python get_server.py yahoo.com
    python get_server.py 10.0.0.0/24
    """
    sys.exit(0)

def status_report(methods, target_count):
    print "\n[*] Targets acquired: %s (IP count: %s)" %  (sys.argv[-1], target_count)
    print "[*] Using Method(s): ",
    for method in methods: print method,

def scan(target, methods, verbose):
    output =[]
    sys.stdout.flush()
    for method in methods:
        if not method.endswith("://"):
            method = method + "://"
        url = str(method)+str(target)
        server = get_server(url)
        #Dont print duplicates
        if server not in output:
            output.append(server)
            if not server.startswith(("Error", "N/A")):
                sys.stdout.write("[+] %-32s Server: %s\n" % (url, server))
            elif verbose:
                sys.stdout.write("[*] %-32s Server: %s\n" % (url, server))

def get_server(url):
    try:
        # ssl cert handling (bypass)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        #HTTP Header Setup
        request = urllib2.Request(url)
        request.add_header('User-agent','Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.131 Safari/537.36')
        request.add_header('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8')
        request.add_header('Accept-Charset', 'ISO-8859-1,utf-8;q=0.7,*;q=0.3')
        request.add_header('Accept-Encoding', 'gzip,deflate,sdch')
        request.add_header('Accept-Language', 'en-US,en;q=0.8,fr;q=0.6')
        request.add_header('Connection', 'keep-alive')

        # Capture response
        response = urllib2.urlopen(request, timeout=2, context=ctx)
        server_info = response.info().getheader('Server')
        if  "None" not in str(server_info):
            server_info
        else:
            server_info = "N/A"
        response.close()
        return server_info
    except urllib2.HTTPError as e:
        server_info = e.info().getheader('Server')
        if "None" not in str(server_info):
            return str(server_info)
        else:
            return "N/A"
    except Exception as e:
        return 'Error %s ' % (e)

def main():
    # Parse cmdline args
    if "-h" in sys.argv or len(sys.argv) == 1: banner()
    methods = arg_parser(flag='-m', type='list', default=['http://', 'https://'])
    verbose = arg_parser(flag='-v', type='bool', default=False)
    max_threads = arg_parser(flag='-t', type='int', default=4)

    #Start program
    targets = list_targets(sys.argv[-1])
    status_report(methods, len(targets))

    print "\n[*] Starting Scan...\n"
    scan_count = 0
    while scan_count != len(targets):
        threads = []
        #Start Threads
        for x in range(0, max_threads):
            if scan_count != len(targets):
                t = Thread(target=scan, args=(targets[scan_count], methods, verbose,))
                t.daemon = True
                threads.append(t)
                t.start()
                scan_count += 1
        for t in threads:
            t.join(1)
    print "\n[!] Scan Complete\n\n"
    sys.exit(0)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print "\n[!] Key Event Detected...\n\n"
        sys.exit(0)