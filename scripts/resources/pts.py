#!/usr/bin/env python2.7
# Author: m8r0wn

import sys
import os
import re
import time
import dns.resolver
import dns.reversename
import socket
from requests import get
from urllib3 import disable_warnings, exceptions

def list_targets(tinput):
    #--dns in sys.argv will keep the dns name in target list for any script
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
        print "\n[!] Invalid target detected 0000: use -h for more\n\n"
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
                print "[-] Invalid target detected 0010: skipping ", line
    else:
        print "\n[!] Target file %s not found\n\n" % (t)
        sys.exit(0)
    return targets


def cidr24(t):
    targets = []
    try:
        target = t.split("/")
        A1, A2, A3, A4 = target[0].split(".")
        for x in range(0, 255):
            target = A1 + "." + A2 + "." + A3 + "." + `x`
            targets.append(target)
    except:
        print "\n[!] Cidr /24 error 0008: check input and try again\n\n"
        sys.exit(1)
    return targets


def cidr16(t):
    targets = []
    try:
        target = t.split("/")
        A1, A2, A3, A4 = target[0].split(".")
        for x in range(0, 255):
            for y in range(0, 256):
                target = A1 + "." + A2 + "." + `x` + "." + `y`
                targets.append(target)
    except:
        print "\n[!] Cidr /16 error 0007 check input and try again\n\n"
        sys.exit(1)
    return targets


def cidr8(t):
    targets = []
    try:
        target = t.split("/")
        A1, A2, A3, A4 = target[0].split(".")
        for x in range(0, 255):
            for y in range(0, 256):
                for z in range(0, 256):
                    target = A1 + "." + `x` + "." + `y` + "." + `z`
                    targets.append(target)
    except:
        print "\n[!] Cidr /8 error 0006: check input and try again\n\n"
        sys.exit(1)
    return targets


def addr_range(t):
    targets = []
    single_ip = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    try:
        A, B = t.split("-")
        if not single_ip.match(A):
            print "\n[!] Invalid IP detected 0001: check input and try again\n\n"
            sys.exit(0)
        A1, A2, A3, A4 = A.split(".")
        for x in range(int(A4), int(B) + 1):
            target = A1 + "." + A2 + "." + A3 + "." + `x`
            targets.append(target)
    except:
        print("\n[!] Target range error 0005: check input and try again\n\n")
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
                for name in dns_lookup(target, 'A'):
                    targets.append(str(name))
            #IP input validation
            elif single_ip.match(target):
                targets.append(target)
            else:
                print "[-] Invalid target detected 0002: skipping ", target
    except:
        print("[-] Multiple target error 0004: check input and try again\n\n")
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
                if single_ip.match(d) or "--dns" in sys.argv:
                    targets.append(d)
                else:
                    for name in dns_lookup(d, 'A'):
                        targets.append(str(name))
        elif "--dns" in sys.argv:
            targets.append(t)
        else:
            #single domain name yahoo.com
            for name in dns_lookup(t, 'A'):
                targets.append(str(name))
    except:
        print"\n[-] Error 0003: in DNS name resolution\n"
        sys.exit(1)
    return targets


def arg_parser(flag, type, default, **kwargs):
    #False=Exit, 'null'=return blank
    try:
        if type == 'int':
            try:
                return int(sys.argv[sys.argv.index(flag) + 1])
            except:
                if default:
                    if default == None:
                        return ''
                    return default
                else:
                    raise Exception("0011: Invalid %s value" % flag)
        elif type == 'file':
            try:
                filename = sys.argv[sys.argv.index(flag) + 1]
                if os.path.exists(filename):
                    return [line.strip() for line in open(filename)]
            except:
                if default:
                    if default == None:
                        return ''
                    return [line.strip() for line in open(default)]
                else:
                    raise Exception("0012: Invalid %s File" % flag)
        elif type == 'str':
            try:
                return sys.argv[sys.argv.index(flag) + 1]
            except:
                if default:
                    if default == "null":
                        return ''
                    return default
                else:
                    raise Exception("0013: Invalid %s value" % flag)
        elif type == 'list':
            try:
                return [sys.argv[sys.argv.index(flag) + 1]]
            except:
                if default:
                    if default == "null":
                        return []
                    return default
                else:
                    raise Exception("0014: Invalid %s value" % flag)
        elif type == 'bool':
            if flag in sys.argv:
                return True
            else:
                return default
        elif type == 'filename': # Used for key login in ssh_login
            filename = sys.argv[sys.argv.index(flag) + 1]
            if os.path.exists(filename):
                return filename
            elif default == "null":
                return False
            elif default:
                return default
            else:
                raise Exception("0015: Invalid %s value" % flag)
        else:
            raise Exception("0016: Invalid %s detected" % (flag))
    except Exception as e:
        print "\n[!] Arg Parse Error %s" % (e)
        sys.exit(1)


def dns_lookup(target, lookup_type):
    results = []
    try:
        # DNS Query
        res = dns.resolver.Resolver()
        res.timeout = 3
        res.lifetime = 3
        dns_query = res.query(target, lookup_type)
        dns_query.nameservers = ['8.8.8.8', '8.8.4.4']
        # Display Data
        for name in dns_query:
            results.append(str(name))
    except Exception as e:
        #print e
        return False
    return results


def reverse_lookup(ip):
    results = []
    try:
        addr = dns.reversename.from_address(ip)
        results = dns_lookup(addr, "PTR")
    except:
        return False
    return results


def print_success(msg):
    print '\033[1;32m[+]\033[1;m', msg


def print_status(msg):
    print '\033[1;34m[*]\033[1;m', msg


def print_failure(msg):
    print '\033[1;31m[-]\033[1;m', msg


def write_file(file, data):
    if os.path.exists(file):
        option = 'a'
    else:
        option = 'w'
    OpenFile = open(file, option)
    if option == 'w':
        OpenFile.write('%s' % (data))
    else:
        OpenFile.write('\n%s' % (data))
    OpenFile.close()


def timestamp():
    return time.strftime('%d-%m-%y_%H_%M')


def banner_grab(server, port):
    try:
        socket.setdefaulttimeout(3)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((server, port))
        banner = sock.recv(1024)
        if banner[-1] == "\n":
            banner=banner[:-1]
        return banner
    except KeyboardInterrupt:
        print "\n[!] Key Event Detected...\n\n"
        sys.exit(0)
    except:
        return False


def web_request(link):
    #Disable ssl warnings
    disable_warnings(exceptions.InsecureRequestWarning)
    header_data = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'}
    #.status_code  #.elapsed.total_seconds() #.text #.content #.headers
    try:
        return get(link, headers=header_data, verify=False, timeout=3)
    except Exception as e:
        return e