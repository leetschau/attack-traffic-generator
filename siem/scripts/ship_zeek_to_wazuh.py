#!/usr/bin/env python3
"""Ship Zeek JSON logs to Wazuh manager via UDP syslog.

Alternative to the localfile ingest path: useful when Zeek logs live on a host
that cannot share a volume with the Wazuh manager (e.g. the autorange VMs).
Requires enabling remote syslog collection on the manager:

    <remote>
      <connection>syslog</connection>
      <port>514</port>
      <allowed-ips>192.168.56.0/24</allowed-ips>
    </remote>

Usage:
    python ship_zeek_to_wazuh.py --dir ../zeek_logs --host 192.168.56.33 --port 514

Tails conn*.log, dns*.log, ssl*.log, http*.log (each line is a JSON object) and
sends one syslog line per record. Re-reads new content every poll interval.
"""
from __future__ import annotations

import argparse
import json
import socket
import time
from pathlib import Path


PATTERNS = ("conn*.log", "dns*.log", "ssl*.log", "http*.log", "files*.log")


def _facility_priority() -> int:
    return 5 * 8 + 6  # local0, informational


def _iter_records(path: Path, offset: int):
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        fh.seek(offset)
        for line in fh:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            yield line, obj


def _send(sock: socket.socket, host: str, port: int, obj: dict, raw: str) -> None:
    src = obj.get("id.orig_h", "?")
    dst = obj.get("id.resp_h", "?")
    dport = obj.get("id.resp_p", "?")
    msg = f"zeek_conn src={src} dst={dst} dport={dport} {raw[:900]}"
    packet = f"<{_facility_priority()}>{msg}"
    sock.sendto(packet.encode("utf-8", errors="replace"), (host, port))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dir", required=True, help="Directory holding Zeek JSON logs.")
    ap.add_argument("--host", default="127.0.0.1", help="Wazuh manager host.")
    ap.add_argument("--port", type=int, default=514, help="Wazuh syslog port.")
    ap.add_argument("--interval", type=float, default=2.0, help="Poll seconds.")
    args = ap.parse_args()

    root = Path(args.dir)
    offsets: dict[Path, int] = {}

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        print(f"Shipping Zeek logs from {root} to {args.host}:{args.port}")
        while True:
            files: list[Path] = []
            for pat in PATTERNS:
                files.extend(sorted(root.glob(pat)))
            for path in files:
                off = offsets.get(path, 0)
                try:
                    for raw, obj in _iter_records(path, off):
                        _send(sock, args.host, args.port, obj, raw)
                        offsets[path] = off
                except FileNotFoundError:
                    continue
                else:
                    offsets[path] = path.stat().st_size if path.exists() else offsets[path]
            time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
