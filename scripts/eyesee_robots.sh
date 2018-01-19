#!/usr/bin/env bash

# Author: m8r0wn
# Script: eyesee_robots.sh

# Description:
# Grabs the robots.txt file of a website
# and uses Eye Witness to view the contents
# of each page found in the file.

# Usage:
# ./eye_see.sh http://example-site.com

# Set path to Eye Witness (no trailing "/")
# git clone https://github.com/ChrisTruncer/EyeWitness
ew_path="/root/Desktop/EyeWitness"

for x in $(curl $1/robots.txt)
do
	if [[ $x == /* ]]
	then
		echo $1$x >> tmp.txt
	fi
done

# Start EyeWitness
python $ew_path/EyeWitness.py -f tmp.txt --web --user-agent "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36" --no-prompt --jitter 5 --threads 2 --timeout 5 --max-retries 2

# Cleanup
if [ -f ./tmp.txt ]; then rm -rf tmp.txt; fi