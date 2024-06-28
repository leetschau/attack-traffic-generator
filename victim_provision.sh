#!/bin/bash

cp /vagrant/data/shell.elf .
chmod 755 shell.elf
nohup ./shell.elf 1> /tmp/beacon.out 2> /tmp/beacon.err &
echo "beacon started!"
