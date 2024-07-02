#!/bin/bash

vagrant destroy -f
rm -rf data; mkdir data

./script_generator attacker_provision.templ range.yml > data/attacker_provision
./script_generator victim_provision.templ range.yml > data/victim_provision
./script_generator handler.rc.templ range.yml > data/handler.rc
echo Provision scripts generated!

vagrant up
sleep 10
vagrant ssh attacker -c 'tmux send -t collector:0 "shell" ENTER'
sleep 2
vagrant ssh attacker -c 'tmux send -t collector:0 "bash /vagrant/c2commands" ENTER'
echo C2 commands executed!
