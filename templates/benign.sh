#!/bin/bash

function browse {
  sleep $1
  curl $2
  mech-dump --images $2 | grep -E '^https*://' > /tmp/images
  for img in $(cat /tmp/images); do
    curl $img
  done
}

echo $(whoami) "on host" $(hostname) "surfing the Internet casually ..."

sudo apt-get -y update && sudo apt-get -y install libwww-mechanize-perl
mech-dump --links {{ benign.url_generator }} | grep -E "^https*://.*/$" | sort | uniq | shuf -n {{ benign.url_number }} > /tmp/urls
export http_proxy="http://192.168.56.33:3128" https_proxy="http://192.168.56.33:3128"

{%- set pmin = benign.pause_interval.min %}
{%- set pmax = benign.pause_interval.max %}
for url in $(cat /tmp/urls); do
  browse $(shuf -i {{ pmin }}-{{ pmax }} -n 1) $url >> /vagrant/benign.log &
done
