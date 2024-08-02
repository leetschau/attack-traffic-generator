# Attack Traffic Generator

Generate attack traffic automatically with specified parameters
between beacon and team server of Metasploit framework and Cobalt Strike.

## Range Setup and traffic generation

Virtualbox and [vagrant](https://github.com/hashicorp/vagrant) is used for
range setup and traffic collection.

By running `vagrant up`, vagrant pull the following boxes automatically:

* kalilinux/rolling:2024.2.0
* ubuntu/trusty64:20191107.0.0
* stegru/win10-build:1.8.7

### Usage

```sh
. .venv/bin/activate
pip install -r requirements.txt
python startrange.py -h
```

### Development

```sh
. .venv/bin/activate
pip install -r dev-requirements.txt
ipython
```

The project metadata and dependencies are defined in pyproejct.toml.
After changing it, run the following commands to regenerate requirement files
and update virtualenv:
```sh
pip install pip-tools
pip-compile -o requirements.txt pyproject.toml
pip-compile --extra dev -o dev-requirements.txt pyproject.toml
pip-sync dev-requirements.txt
```

## Packet Study

Docker or [Podman](https://podman.io/) is needed to provision external dependencies.

```sh
podman run --rm -v .:/app -w /app zeek/zeek:lts zeek local -r /app/traffic.pcap
```

