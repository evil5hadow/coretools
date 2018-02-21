#!/usr/bin/env bash

# Author: m8r0wn
# Script: eyesee.sh

# Description:
# Performs nmap for host discovery and passes
# scan results off to Eye Witness to get a snap
# shot of service running on the network.

# Usage:
# ./eye_see.sh [Path to EyeWitness] [target_ip/range]
# ./eye_see.sh ../EyeWitness/EyeWitness.py 10.11.1.0/24


# Nmap Host Discovery Scan
nmap_out="./nmap_out.xml"
ports="80,8080,443,8443,5900,5800,5901,3389"
nmap -sT -p $ports -oX $nmap_out $2

# Capture screenshot with EyeWitness
python $1 -x $nmap_out --all-protocols --user-agent "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36" --no-prompt --jitter 5 --threads 2 --timeout 5 --max-retries 2

# Cleanup
if [ -f ./geckodriver.log ]; then rm -rf geckodriver.log; fi
if [ -f ./parsed_xml.txt ]; then rm -rf parsed_xml.txt; fi
if [ -f ./$nmap_out ]; then rm -rf $nmap_out; fi