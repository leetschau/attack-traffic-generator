#!/bin/bash

vagrant destroy -f
rm -rf data; mkdir data
vagrant up
sleep 10
vagrant ssh attacker -c 'tmux send -t collector:0 "ls -l" ENTER'
