#!/usr/bin/env bash

# Author: m8r0wn
# Script: eyesee_robots.sh

# Description:
# Grabs the robots.txt file of a website
# and uses Eye Witness to view the contents
# of each page found in the file.

# Usage:
# ./eye_see.sh [Path to EyeWitness] [Site]
# ./eye_see.sh ../EyeWitness/EyeWitness.py http://example-site.com

for x in $(curl $2/robots.txt)
do
	if [[ $x == /* ]]
	then
		echo $2$x >> tmp.txt
	fi
done

# Start EyeWitness
python $1 -f tmp.txt --web --user-agent "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36" --no-prompt --jitter 5 --threads 2 --timeout 5 --max-retries 2

# Cleanup
if [ -f ./tmp.txt ]; then rm -rf tmp.txt; fi