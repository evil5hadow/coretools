#!/usr/bin/env python2.7

# Author: m8r0wn
# Script: list_targets.py

# Disclaimer:
# This tool was designed to be used only with proper
# consent. Use at your own risk.

import sys
import dns_lookup
import os
import re

def banner():
    print """
            list_targets.py
     -----------------------------------
Script to take user input via command line arguments,
and return a list of IP Addresses.

Input:
    + /24 CIDR Block
    + .txt files
    + comma separated: IP,IP,IP
    + Single DNS Names
    + Multiple DNS Names one.com,two.com,three.com
    + Range 10.0.0.1-50

Usage:
    python list_targets source_file.txt
    python list_targets 10.0.0.0/24
    """
    sys.exit(0)

def list_targets(tinput):
    single_ip = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    ip_range = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}$")
    dns_end = re.compile("^.+\.[a-z|A-Z]{2,}$")

    #Txt File
    if ".txt" in tinput:
        return txt_file(tinput)

    #CIDR Block
    elif tinput.endswith("/24"):
        return cidr24(tinput)
    elif tinput.endswith("/16"):
        return cidr16(tinput)
    elif tinput.endswith("/8"):
        return cidr8(tinput)

    #Range
    elif ip_range.match(tinput):
        return addr_range(tinput)

    #DNS Name
    elif dns_end.match(tinput):
        return dns_name(tinput)

    #Multiple IP
    elif "," in tinput:
        return multiple(tinput)

    #Single IP
    elif single_ip.match(tinput):
        return [tinput]
    else:
        print "\n[!] Invalid target detected, use -h for more\n\n"
        sys.exit(0)

def txt_file(t):
    targets = []
    single_ip = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    dns_end = re.compile("^.+\.[a-z|A-Z]{2,}$")
    if os.path.exists(t):
        tmp = [line.strip() for line in open(t)]
        #Input validation of targets
        for line in tmp:
            #If DNS name in line, lookup A record
            if dns_end.match(line):
                for name in dns_lookup(line, 'A'):
                    targets.append(str(name))
            #Else if not valid IP, exit
            elif single_ip.match(line):
                targets.append(line)
            else:
                print "[-] Invalid target detected, skipping ", line
    else:
        print "\n[!] Target file %s not found\n\n" % (t)
        sys.exit(0)
    return targets

def cidr24(t):
    targets = []
    try:
        target = t.split("/")
        A1, A2, A3, A4 = target[0].split(".")
        for x in range(0, 256):
            target = A1 + "." + A2 + "." + A3 + "." + `x`
            targets.append(target)
    except:
        print "\n[!] Cidr /24 error, check input and try again\n\n"
        sys.exit(1)
    return targets

def cidr16(t):
    targets = []
    try:
        target = t.split("/")
        A1, A2, A3, A4 = target[0].split(".")
        for x in range(0, 256):
            for y in range(0, 256):
                target = A1 + "." + A2 + "." + `x` + "." + `y`
                targets.append(target)
    except:
        print "\n[!] Cidr /16 error, check input and try again\n\n"
        sys.exit(1)
    return targets

def cidr8(t):
    targets = []
    try:
        target = t.split("/")
        A1, A2, A3, A4 = target[0].split(".")
        for x in range(0, 256):
            for y in range(0, 256):
                for z in range(0, 256):
                    target = A1 + "." + `x` + "." + `y` + "." + `z`
                    targets.append(target)
    except:
        print "\n[!] Cidr /8 error, check input and try again\n\n"
        sys.exit(1)
    return targets

def addr_range(t):
    targets = []
    single_ip = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    try:
        A, B = t.split("-")
        if not single_ip.match(A):
            print "\n[!] Invalid IP detected, check input and try again\n\n"
            sys.exit(0)
        A1, A2, A3, A4 = A.split(".")
        for x in range(int(A4), int(B) + 1):
            target = A1 + "." + A2 + "." + A3 + "." + `x`
            targets.append(target)
    except:
        exit("\n[!] Target range error, check input and try again\n\n")
        sys.exit(0)
    return targets

def multiple(t):
    targets = []
    single_ip = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    dns_end = re.compile("^.+\.[a-z|A-Z]{2,}$")
    try:
        for target in t.split(","):
            #Check if dns name in list
            if dns_end.match(target):
                for name in dns_lookup.dns_lookup(target, 'A'):
                    targets.append(str(name))
            #IP input validation
            elif single_ip.match(target):
                targets.append(target)
            else:
                print "[-] Invalid target detected, skipping ", target
    except:
        exit("[-] Multiple target error, check input and try again\n\n")
        sys.exit(1)
    return targets

def dns_name(t):
    single_ip = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    targets = []
    try:
        #multiple domain names yahoo.com,google.com
        if "," in t:
            for d in t.split(","):
                #check for IP in list of DNS names
                if single_ip.match(d):
                    targets.append(d)
                for name in dns_lookup.dns_lookup(d, 'A'):
                    targets.append(str(name))
        else:
            #single domain name yahoo.com
            for name in dns_lookup.dns_lookup(t, 'A'):
                targets.append(str(name))
    except:
        print"\n[-] Error T002: Error in DNS name resolution\n[*] Ensure proper input is provided, use -h for more\n\n"
        sys.exit(1)
    return targets

def arg_parser(name, flag, type, default, **kwargs):
    try:
        if type == int:
            return int(sys.argv[sys.argv.index(flag) + 1])
        elif type == file:
            filename = sys.argv[sys.argv.index(flag) + 1]
            if os.path.exists(filename):
                return [line.strip() for line in open(filename)]
            else:
                raise Exception("Input file not found")
        elif type == str:
            return sys.argv[sys.argv.index(flag) + 1]
        elif type == list:
            return [sys.argv[sys.argv.index(flag) + 1]]
        elif type == bool:
            if flag in sys.argv:
                return True
            else:
                return default
        # Used for key login in ssh_login
        elif type == 'filename':
            filename = sys.argv[sys.argv.index(flag) + 1]
            if os.path.exists(filename):
                return filename
        else:
            raise Exception("Invalid type detected")
    except Exception, e:
        # Return default value -- used for default wordlists in brute force scripts
        if type == file and default:
            print "[*] Arg Parse Error: Invalid wordlist, reverting to default"
            return [line.strip() for line in open(default)]
        # Return default value
        elif type != file and default:
            return default
        # Default=None will return blank variable
        elif default == None:
            return ''
        # Default=False will exit program for invalid value (except bool)
        else:
            print "[!] Arg Parse Error: %s\n" % (e)
            sys.exit(0)

def print_success(msg):
    print '\033[1;32m[+]\033[1;m', msg

def print_status(msg):
    print '\033[1;34m[*]\033[1;m', msg

def print_failure(msg):
    print '\033[1;31m[-]\033[1;m', msg

def main():
    # Help banner
    if "-h" in sys.argv or len(sys.argv) == 1: banner()

    if sys.argv[-1]:
        print "[*] Enumerating Targets for: ", sys.argv[-1]
        targets = list_targets(sys.argv[-1])
        for t in targets:
            print "    ",t

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print "\n[!] Key Event Detected...\n\n"
        sys.exit(0)