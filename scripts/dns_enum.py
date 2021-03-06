#!/usr/bin/env python2.7

# Author: m8r0wn
# Script: dns_enum.py

# Disclaimer:
# This tool was designed to be used only with proper
# consent. Use at your own risk.

import sys
import dns.zone
import os
from resources.pts import arg_parser, dns_lookup

def banner():
    print '''
                    dns_enum.py
         -----------------------------------
Script to perform Subdomain enumeration via DNS and
DNS zone transfers on the targeted domain.

DNS Zone Transfer:
    -z                          Perform DNS Zone Transfer

Sub-Domain Brute Force:
    -s                          Subdomain Brute force
    -w [file.txt]               custom word list

Usage:
    python dns_enum.py -z zonetransfer.me
    python dns_enum.py -s example.com
    '''
    sys.exit(0)

def subdomain_enum(target):
    print '[*] Sub-Domain Enumeration\n' + '-'*40
    #Get word list
    subs = arg_parser(flag='-w', type='file', default='../wordlists/dns_enum_subdomains.txt')
    # DNS query for each subdomain
    for s in subs:
        query = s+'.'+target
        try:
             dns_query = dns_lookup(target, 'A')
             for resp in dns_query:
                 # Print Output
                 space_num = len(sys.argv[-1]) + 10
                 print '%-*s--> %s' % (space_num, query, resp)
        except Exception as e:
            pass

def zone_transfer(target):
    print '[*] DNS Zone Transfer\n' + '-' * 40
    #Get Name Servers
    for ns_name in dns_lookup(target, 'NS'):
        try:
            z = dns.zone.from_xfr(dns.query.xfr(str(ns_name), target, lifetime=5))
            names = z.nodes.keys()
            names.sort()
            for n in names:
                #Output
                print (z[n].to_text(n))
        except Exception as e:
            print "[!] Error: ",e

def main():
    try:
        # Parse User Input
        if "-h" in sys.argv or len(sys.argv) == 1: banner()

        #quick target input validation
        target = sys.argv[-1]
        if "://" in target or "." * 2 in target:
            print "\n[!] DNS_enum Target Error, use -h for more\n\n"
            sys.exit(0)

        #Start
        if "-z" in sys.argv:
            zone_transfer(target)
        elif "-s" in sys.argv:
            subdomain_enum(target)

        else:
            print "\n[-] No options selected, use -h for more information\n\n"
            sys.exit(0)

    except Exception as e:
        print "[!] Error parsing initial options: %s" % (e)
        sys.exit(0)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print "\n[!] Key Event Detected...\n\n"
        sys.exit(0)