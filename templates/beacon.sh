#!/bin/bash

beacon_file=$1
cp /vagrant/$beacon_file .
chmod 755 $beacon_file
nohup ./$beacon_file &> /vagrant/$beacon_file.log &
echo "$beacon_file started!"
