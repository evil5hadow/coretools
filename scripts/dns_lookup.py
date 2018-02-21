#!/usr/bin/env python2.7

# Author: m8r0wn
# Script: dns_lookup.py

# Disclaimer:
# This tool was designed to be used only with proper
# consent. Use at your own risk.

import sys
from resources.pts import arg_parser, dns_lookup, list_targets, reverse_lookup

def banner():
    print """
           dns_lookup.py
   -----------------------------------
    Perform DNS and reverse DNS lookups

Options:
    -t [type]       DNS lookup types:
                    [A,NS,MX,TXT,CNAME,HINFO,PTR,SOA,SPF,SRV,RP]

    -t all          Lookup all DNS types

    -r              reverse lookup

Usage:
    python dns_lookup.py -t MX google.com
    python dns_lookup.py -t all yahoo.com
    python dns_lookup -r 172.217.3.46-50
    """
    sys.exit(0)

def main():
    # Define Required Variables
    all_types = ['A','NS','MX','TXT','CNAME','HINFO','PTR','SOA','SPF','SRV','RP']

    # Parse cmdline args
    if "-h" in sys.argv or len(sys.argv) == 1: banner()
    sys.argv.insert(0, "--dns") #keep all dns names in tact during listing of targets
    hosts = list_targets(sys.argv[-1])
    lookup_type = arg_parser(flag='-t', type='str', default="null")
    rev = arg_parser(flag='-r', type='bool', default=False)

    # Start DNS lookup
    if lookup_type:
        print '[*] DNS Lookup\n' + '-' * 15
        for t in hosts:
            if 'all' in lookup_type:
                for d in all_types:
                    results = dns_lookup(t, d)
                    if results:
                        print "\n[+] %s records for %s" % (d, t)
                        for x in results:
                            print "    ", x
            else:
                results = dns_lookup(t, lookup_type)
                if results:
                    print "\n[+] %s records for %s" % (lookup_type, t)
                    for x in results:
                        print "    ", x

    # Reverse DNS Lookup
    elif rev:
        print '[*] Reverse DNS Lookup\n' + '-' * 22
        for t in hosts:
            results = reverse_lookup(t)
            if results:
                for x in results:
                    print "[+] %s (%s)" % (x, t)
    else:
        print "[*] No lookup argument provided, see -h for more\n\n"
        sys.exit(0)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print "\n[!] Key Event Detected...\n\n"
        sys.exit(0)