from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Iterable

from .models import BeaconFinding


_SUMMARY_COLS = [
    "src_ip",
    "dst_ip",
    "dst_port",
    "proto",
    "service",
    "connection_count",
    "interval_mean",
    "interval_jitter",
    "ts_score",
    "ds_score",
    "beacon_score",
]


def _summary_rows(findings: Iterable[BeaconFinding]) -> list[dict]:
    return [
        {
            **{c: f.as_dict().get(c) for c in _SUMMARY_COLS},
            "techniques": ",".join(t.id for t in f.techniques),
        }
        for f in findings
    ]


def render_table(findings: list[BeaconFinding]) -> str:
    rows = _summary_rows(findings)
    if not rows:
        return "No beaconing channels detected."
    try:
        import polars as pl

        df = pl.DataFrame(rows)
        with pl.Config(
            tbl_rows=50,
            tbl_cols=20,
            tbl_width_chars=220,
            set_tbl_hide_dataframe_shape=True,
        ):
            return df.to_pandas().to_string(index=False)
    except Exception:
        return _plain_table(rows)


def _plain_table(rows: list[dict]) -> str:
    headers = _SUMMARY_COLS + ["techniques"]
    widths = {h: max(len(h), *(len(str(r.get(h, ""))) for r in rows)) for h in headers}
    sep = "  ".join("-" * widths[h] for h in headers)
    out = ["  ".join(h.ljust(widths[h]) for h in headers), sep]
    for r in rows:
        out.append("  ".join(str(r.get(h, "")).ljust(widths[h]) for h in headers))
    return "\n".join(out)


def render_json(findings: list[BeaconFinding]) -> str:
    return json.dumps([f.as_dict() for f in findings], indent=2)


def render_csv(findings: list[BeaconFinding]) -> str:
    if not findings:
        return ""
    buf = io.StringIO()
    fieldnames = list(findings[0].as_dict().keys())
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for f in findings:
        row = f.as_dict()
        row["techniques"] = json.dumps(row["techniques"])
        writer.writerow(row)
    return buf.getvalue()


def write_outputs(
    findings: list[BeaconFinding], outdir: str | Path, formats=("json", "csv")
) -> dict[str, Path]:
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}
    if "json" in formats:
        p = out / "beacon_findings.json"
        p.write_text(render_json(findings), encoding="utf-8")
        written["json"] = p
    if "csv" in formats:
        p = out / "beacon_findings.csv"
        p.write_text(render_csv(findings), encoding="utf-8")
        written["csv"] = p
    return written
