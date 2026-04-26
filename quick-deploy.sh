#!/bin/bash
# Quick deployment for RedBadger

set -e

# Clone or copy files
echo "Deploying RedBadger Security Platform..."

# Install dependencies
if command -v apt-get &> /dev/null; then
    sudo apt-get update
    sudo apt-get install -y python3 python3-pip nmap
elif command -v yum &> /dev/null; then
    sudo yum install -y python3 python3-pip nmap
elif command -v apk &> /dev/null; then
    sudo apk add python3 py3-pip nmap
fi

# Install Python packages
pip3 install --user requests psutil flask

# Run RedBadger
python3 redbadger.py