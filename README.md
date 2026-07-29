# Attack Traffic Generator

Generate attack traffic automatically with specified parameters
between beacon and team server of Metasploit framework and Cobalt Strike,
then **detect** that traffic end-to-end: an offline beaconing analyzer
(`tranalyzer`) plus a live Wazuh SIEM stack.

The project has three layers:

1. **Range / traffic generation** — Vagrant lab running MSF + Cobalt Strike C2
   against Linux/Windows victims with benign background traffic (this file,
   `range.yml`, `templates/`, `startrange.py`).
2. **Offline detection** — `tranalyzer`, a Zeek `conn.log` beaconing detector
   with MITRE ATT&CK mapping (`src/c2_traffic_analyzer/`).
3. **Live SIEM detection** — single-node Wazuh stack with custom C2 rules
   (`siem/`).

The methodology and ATT&CK mapping are documented in
[`docs/detection-approach.md`](docs/detection-approach.md).

## Range Setup and Traffic Generation

VirtualBox and [vagrant](https://github.com/hashicorp/vagrant) is used for range setup and traffic collection.

By running `vagrant up`, vagrant pulls the following boxes automatically:

* KaliLinux/rolling:2024.2.0
* Ubuntu/trusty64:20191107.0.0
* stegru/win10-build:1.8.7

### Usage

```sh
. .venv/bin/activate
pip install -r requirements.txt
python startrange.py -h
```

`python startrange.py -r` builds the range, starts the C2 servers, deploys
beacons, and captures `traffic.pcap` with tshark.

### Development

```sh
. .venv/bin/activate
pip install -r dev-requirements.txt
ipython
```

The project metadata and dependencies are defined in `pyproject.toml`.
After changing it, run the following commands to regenerate requirement files
and update virtualenv:

```sh
pip install pip-tools
pip-compile -o requirements.txt pyproject.toml
pip-compile --extra dev -o dev-requirements.txt pyproject.toml
pip-sync dev-requirements.txt
```

## Packet Study & Zeek Logs

Docker or [Podman](https://podman.io/) is needed to provision external
dependencies. Generate **JSON** Zeek logs (required by the SIEM path; the
Python detector also reads TSV):

```sh
mkdir -p zeek_logs
podman run --rm -v "$PWD/autorange:/in" -v "$PWD/zeek_logs:/out" -w /out \
  zeek/zeek:lts zeek -r /in/traffic.pcap \
  local "Policy/tuning/json-logs.zeek" LogAscii::use_json=T
```

## Offline detection: `tranalyzer`

Detect C2 beaconing channels in Zeek `conn.log` and map them to MITRE
ATT&CK. Uses an IQR-based regularity score (RITA-style) on connection
intervals, response sizes, and durations.

```sh
pip install -e .            # installs the `tranalyzer` console script
tranalyzer zeek_logs/conn.log --min-score 0.7 --format table
tranalyzer zeek_logs/conn.log --format json -o findings/
```

Key flags: `-n/--min-connections`, `-s/--min-score`, `--min-ts-score`,
`--skip-internal`, `--no-attack`. Exit code is non-zero when beacons are
found, so it composes well with CI.

Tests:

```sh
pytest -q
```

## Live SIEM detection: Wazuh

A single-node Wazuh stack (manager + indexer + dashboard) with custom rules
for the range's C2 ports, Cobalt Strike team server, TLS-on-non-standard-port,
and frequency-based beaconing. See [`siem/README.md`](siem/README.md) for the
full runbook.

```sh
cd siem
docker compose up -d
./scripts/enable_zeek_ingest.sh
docker exec siem-wazuh.manager-1 tail -f /var/ossec/logs/alerts/alerts.json
```

## Layout

```
startrange.py            build the range from range.yml + templates/
templates/               Jinja2 templates (Vagrantfile, C2 scripts, beacons)
src/c2_traffic_analyzer/ offline beaconing detector + ATT&CK mapping
tests/                   pytest suite (synthetic Zeek conn.log fixtures)
siem/                    Wazuh compose, custom rules, ingest scripts
docs/                    detection methodology + ATT&CK mapping
range.yml                range topology / C2 listener parameters
```
