from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Iterable

from .attack_mapping import annotate
from .beacon import detect_beacons
from .models import BeaconFinding, DetectionConfig
from .reporter import render_csv, render_json, render_table, write_outputs
from .zeek_loader import load_conn_log


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tranalyzer",
        description=(
            "Detect C2 beaconing channels in Zeek conn.log traffic and map "
            "them to MITRE ATT&CK techniques."
        ),
    )
    p.add_argument(
        "conn_log",
        nargs="+",
        help="One or more Zeek conn.log files (TSV or JSON-header variants).",
    )
    p.add_argument(
        "-n", "--min-connections", type=int, default=10,
        help="Minimum connections per channel to consider (default: 10).",
    )
    p.add_argument(
        "-s", "--min-score", type=float, default=0.7,
        help="Minimum beacon score in [0,1] to flag (default: 0.7).",
    )
    p.add_argument(
        "--min-ts-score", type=float, default=0.5,
        help="Minimum time-regularity sub-score (default: 0.5).",
    )
    p.add_argument(
        "--min-timespan", type=float, default=30.0,
        help="Minimum channel timespan in seconds (default: 30).",
    )
    p.add_argument(
        "--skip-internal", action="store_true",
        help="Skip channels where either endpoint is RFC1918 internal.",
    )
    p.add_argument(
        "--format", choices=("table", "json", "csv"), default="table",
        help="Output format (default: table).",
    )
    p.add_argument(
        "-o", "--outdir", help="Write json+csv findings to this directory.",
    )
    p.add_argument(
        "--no-attack", action="store_true",
        help="Skip MITRE ATT&CK annotation.",
    )
    return p


def _load_all(paths: list[str]):
    conns = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            logs = sorted(p.glob("conn*.log"))
            if not logs:
                print(f"warning: no conn*.log under {p}", file=sys.stderr)
            for sub in logs:
                conns.extend(load_conn_log(sub))
        else:
            conns.extend(load_conn_log(p))
    return conns


def run(args: argparse.Namespace) -> int:
    config = DetectionConfig(
        min_connections=args.min_connections,
        min_beacon_score=args.min_score,
        min_ts_score=args.min_ts_score,
        min_timespan_seconds=args.min_timespan,
        skip_internal_pairs=args.skip_internal,
    )
    conns = _load_all(args.conn_log)
    print(f"Loaded {len(conns)} connection records.", file=sys.stderr)

    findings = detect_beacons(conns, config)
    if not args.no_attack:
        findings = annotate(findings)

    _emit(findings, args)
    if args.outdir:
        written = write_outputs(findings, args.outdir)
        for fmt, path in written.items():
            print(f"wrote {fmt}: {path}", file=sys.stderr)

    print(f"\n{len(findings)} beaconing channel(s) flagged.", file=sys.stderr)
    return 1 if findings else 0


def _emit(findings: Iterable[BeaconFinding], args: argparse.Namespace) -> None:
    materialized = list(findings)
    if args.format == "table":
        print(render_table(materialized))
    elif args.format == "json":
        print(render_json(materialized))
    elif args.format == "csv":
        print(render_csv(materialized))


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
