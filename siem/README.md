# Wazuh SIEM Integration

Feeds the Zeek logs produced by the range into a single-node Wazuh stack and
raises alerts for C2 beaconing using custom detection rules mapped to MITRE
ATT&CK.

```
  autorange VMs                 host                          Wazuh stack (docker)
  --------------                ----                          --------------------
  MSF / CS  ----\              zeek local -r traffic.pcap
  victims  ----- > traffic.pcap ---> zeek_logs/*.log  ---->   wazuh.manager
  benign   ----/               (JSON logs, see below)         (localfile -> rules)
                                                             wazuh.indexer
  (optional) ship_zeek_to_wazuh.py --dir zeek_logs  --syslog--> :514
                                                             wazuh.dashboard :5601
```

The Python detector (`tranalyzer`) does offline beaconing analysis on the same
`zeek_logs/conn.log`; Wazuh does **online alerting** as traffic is replayed.
Together they cover both batch hunting and real-time detection.

## Prerequisites

- Docker (or Podman with `docker-compose` compatibility)
- ~4 GB free RAM for the stack
- Zeek logs in **JSON** format at `../zeek_logs/` (relative to `siem/`)

## 1. Produce JSON Zeek logs

The range writes `autorange/traffic.pcap` (see `templates/c2servers.sh`).
Convert it to JSON Zeek logs so the Wazuh `json` decoder and the rules in
`local_rules.xml` can read fields like `id.resp_p`:

```sh
mkdir -p zeek_logs
podman run --rm -v "$PWD/autorange:/in" -v "$PWD/zeek_logs:/out" -w /out \
  zeek/zeek:lts zeek -r /in/traffic.pcap \
  local "Policy/tuning/json-logs.zeek" \
  LogAscii::use_json=T
```

> TSV logs are still parsed by the Python `tranalyzer`; only the Wazuh path
> requires JSON.

## 2. Start the Wazuh stack

```sh
cd siem
docker compose up -d
```

Wait ~60 s for the indexer, then open the dashboard:
<http://localhost:5601> (default `admin` / `admin`; you will be asked to change it).

The custom rules under `wazuh/config/rules/local_rules.xml` are mounted into
the manager and auto-loaded at startup.

## 3. Enable Zeek log collection

Two equivalent methods; pick one.

**A. Localfile (primary, no extra host config)**

```sh
./scripts/enable_zeek_ingest.sh
```

This injects a `<localfile log_format="json">` block for
`/var/ossec/logs/zeek/conn.log` into the manager and restarts it. The
`zeek_logs/` directory is already mounted read-only at that path.

**B. Syslog shipper (when logs live on a VM without a shared volume)**

Enable remote syslog on the manager (add to `ossec.conf`):

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <allowed-ips>192.168.56.0/24</allowed-ips>
</remote>
```

then run:

```sh
python3 scripts/ship_zeek_to_wazuh.py --dir ../zeek_logs --host 127.0.0.1 --port 514
```

## 4. Watch alerts

```sh
docker exec siem-wazuh.manager-1 tail -f /var/ossec/logs/alerts/alerts.json
```

In the dashboard, go to **Wazuh > Security events** to see grouped alerts.

## Detection catalog

| Rule ID | Level | Trigger | ATT&CK |
|--------:|------:|---------|--------|
| 100100  | 0     | Any Zeek conn event (parent) | - |
| 100101  | 12    | C2 listener on non-standard port (7101-7103, 7202-7203) | T1571, T1071 |
| 100102  | 14    | Cobalt Strike team server (50050) | T1071, T1105 |
| 100103  | 12    | TLS/HTTPS on a non-standard port | T1573.002, T1571 |
| 100110  | 10    | 15+ connections in 120 s, same src+dst (beaconing) | T1071, T1071.001 |
| 100111  | 13    | 40+ connections in 300 s (high-confidence beacon) | T1071 |
| 100120  | 11    | Large response (>= 1 MB) over a flagged C2 channel | T1105 |

Rule ports mirror `range.yml` (`attacker.msf.listener`, `attacker.cobaltstrike`).

## Tuning notes

- `100110` / `100111` use Wazuh frequency rules with `same_source_ip` +
  `same_destination_ip`. Raise `frequency` / `timeframe` to cut false positives
  from legitimate keep-alives (NTP, monitoring agents).
- For production, suppress known-good pairs with `<field>` allow-lists rather
  than disabling the rule.
- The Python `tranalyzer` score (jitter + size regularity) is more precise than
  the count-based SIEM rule; use its `beacon_findings.json` output to validate
  SIEM hits and to feed back allow/deny lists.

## Troubleshooting

- **No alerts**: confirm logs are JSON (`head -1 ../zeek_logs/conn.log` should
  start with `{`), and that the localfile block was injected
  (`docker exec siem-wazuh.manager-1 grep tranalyzer:zeek /var/ossec/etc/ossec.conf`).
- **`9200` / `5601` already in use**: remap ports in `docker-compose.yml`.
- **Manager keeps restarting**: validate `local_rules.xml` with
  `docker exec siem-wazuh.manager-1 /var/ossec/bin/wazuh-logtest -v` against a
  sample JSON line.
