# Attack Traffic Generator

Generate attack traffic automatically with specified parameters
between beacon and team server of Metasploit framework and Cobalt Strike.

## Prerequisites

[Podman](https://podman.io/) is used to provision external dependencies.

Virtualbox and [vagrant](https://github.com/hashicorp/vagrant) is used for
range setup and traffic generation.

By running `vagrant up`, vagrant pull the following boxes automatically:

* kalilinux/rolling:2024.2.0
* ubuntu/trusty64:20191107.0.0
* stegru/win10-build:1.8.7

## Environment Setup

```sh
podman build . -t auto-attack  # build container
podman run --rm -it -v .:/app auto-attack install  # install Python packages
```

## Usage

Range setup and traffic generation:
```sh
podman run --rm -it -v .:/app auto-attack run python startrange.py -h
```

Packet study:
```sh
podman run --rm -it -v .:/app auto-attack run scapy
```
