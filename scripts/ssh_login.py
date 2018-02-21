#!/usr/bin/env python2.7

# Author: m8r0wn
# Script: ssh_login.py

# Disclaimer:
# This tool was designed to be used only with proper
# consent. Use at your own risk.

import paramiko
from resources.pts import list_targets, print_success, print_failure, print_status, arg_parser
import sys

def banner():
    print """
              ssh_login.py
    -----------------------------------
Test SSH creds and execute command(s) once authenticated.
This can be done on one or multiple hosts.

OPTIONS:
    -u              Username value
    -U              user.txt file

    -p              Password value
    -P              Pass.txt file

    -k              key file for authentication
    --port          non-standard SSH port

    -e              Command to execute on login
                        Takes:
                          + single command
                          + cmd.txt file (1 cmd per line)
                          + multiple: 'cmd1&&cmd2&&cmd3'
USAGE:
    python ssh_login -u root -p toor -e 'ls' 10.11.1.1
    python ssh_login -u tswift -k my_key.cert 192.168.1.5

NOTE: Having trouble with inputs? Use '' around input
    """
    sys.exit(0)

def ssh_login(target, port, auth_key, user, passwd, commands):
    #Login Check
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if auth_key:
           paramiko.RSAKey.from_private_key_file(auth_key)
           client.connect(target, port=port, username=user, password=passwd, key_filename=auth_key, timeout=2)
        else:
            client.connect(target, port=port, username=user, password=passwd, timeout=2)
        session = client.get_transport().open_session()
        print_success("Success %s \'%s\':\'%s\' key=%s"% (target, user, passwd, bool(auth_key)))
    except KeyboardInterrupt:
        print "\n[!] Key Event Detected...\n\n"
        sys.exit(0)
    except Exception as e:
        #print e
        print_failure("Login Failed %s \'%s\':\'%s\' key=%s" % (target, user, passwd, bool(auth_key)))
        return False
    #Code Exec
    if session.active and commands:
        try:
            session.exec_command('bash -s')
            for cmd in commands:
                print_status("COMMAND: %s" % (cmd))
                session.send_ready()
                session.send('%s\n' % (cmd))
                session.recv_ready()
                print session.recv(4096)
        except KeyboardInterrupt:
            print "\n[!] Key Event Detected...\n\n"
            sys.exit(0)
        except Exception as e:
            print "[!] Error in ssh_login:",e
    client.close()

def main():
    # Parse user input
    if "-h" in sys.argv or len(sys.argv) == 1: banner()
    try:
        if "-U" in sys.argv:
            users = arg_parser(flag='-U', type='file', default=False)
        else:
            users = arg_parser(flag='-u', type='list', default=False)

        if "-P" in sys.argv:
            passwds = arg_parser(flag='-P', type='file', default=False)
        else:
            passwds = arg_parser(flag='-p', type='list', default="null")

        key = arg_parser(flag='-k', type='filename', default=None)
        port = arg_parser(flag='--port', type='int', default=22)

        if "-e" in sys.argv:
            cmd = []
            cmd_input = sys.argv[sys.argv.index("-e")+1]
            if cmd_input.endswith(".txt"):
                cmd = arg_parser(name='commands', flag='-e', type=file, default=False)
            elif "&&" in cmd_input:
                for x in cmd_input.split("&&"):
                    cmd.append(x)
            else:
                cmd = [cmd_input]
        else: cmd = False

        #Start ssh_login
        print "\n[*] Starting ssh_login\n", "-"*29
        for target in list_targets(sys.argv[-1]):
            for user in users:
                for passwd in passwds:
                    #single key
                    if key:
                        ssh_login(target, port, key, user, passwd, cmd)
                    #Iterate through passwd list
                    else:
                        ssh_login(target,port,key,user,passwd,cmd)
        print "\n[*] Scan Complete\n"
    except Exception as e:
        print "[!] Main Error:",e

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print "\n[!] Key Event Detected...\n\n"
        sys.exit(0)