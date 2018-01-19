#!/usr/bin/env python2.7

# Author: m8r0wn
# Script: dns_lookup.py

# Disclaimer:
# This tool was designed to be used only with proper
# consent. Use at your own risk.

import dns.resolver
import dns.reversename
import sys
import list_targets

def banner():
    print """
           dns_lookup.py
   -----------------------------------
    Perform DNS and reverse DNS lookups

Options:
    -t [type]       DNS lookup types:
                    [NS, A, AAAA, MX, TXT, CNAME, HINFO, ISDN, PTR, SOA]

    -t all          Lookup all DNS types

    -r              reverse lookup

Usage:
    python dns_lookup.py -t MX google.com
    python dns_lookup.py -t all yahoo.com
    python dns_lookup -r 172.217.3.46
    """
    sys.exit(0)

def dns_lookup(target, lookup_type):
    results = []
    try:
        # DNS Query
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        dns_query = dns.resolver.query(target, lookup_type)
        dns_query.nameservers = ['8.8.8.8', '8.8.4.4']
        # Display Data
        for name in dns_query:
            results.append(str(name))
    except Exception as e:
        print "[!] Error in DNS name resolution: %s" % (e)
    return results

def reverse_lookup(ip):
    results = []
    try:
        addr = dns.reversename.from_address(ip)
        results = dns_lookup(addr, "PTR")
    except Exception as e:
        print "[!] Error in reverse lookup"
        print "[!]", e
    return results

def main():
    # Define Required Variables
    all_types = ['NS', 'A', 'AAAA', 'MX', 'TXT', 'CNAME', 'HINFO', 'ISDN', 'PTR', 'SOA', 'SRV']

    # Parse cmdline args
    if "-h" in sys.argv or len(sys.argv) == 1: banner()
    host = sys.argv[-1]
    lookup_type = list_targets.arg_parser(name='lookup type', flag='-t', type=str, default=None)
    rev = list_targets.arg_parser(name='reverse lookup', flag='-r', type=bool, default=False)

    # Start DNS lookup
    if lookup_type:
        print "[*] Starting DNS Lookup"
        if 'all' in lookup_type:
            for dnstype in all_types:
                print "\n[*] Searching \"%s\" records for %s" % (dnstype, host)
                for x in dns_lookup(host, dnstype):
                    print "    ", x
        else:
            print "\n[*] Searching \"%s\" records for %s" % (lookup_type, host)
            for x in dns_lookup(host, lookup_type):
                print "    ", x
    elif rev:
        print "[*] Reverse DNS Lookup for: %s" % (host)
        for x in reverse_lookup(host):
            print "    ", x
    else:
        print "[*] No lookup argument provided, see -h for more\n\n"
        sys.exit(0)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print "\n[!] Key Event Detected...\n\n"
        sys.exit(0)