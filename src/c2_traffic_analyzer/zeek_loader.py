from __future__ import annotations

from pathlib import Path
from typing import Iterator, Optional

from .models import Connection


_ZEEK_TS_FORMATS = ("%Y-%m-%d-%H-%M-%S.%f", "%Y-%m-%d-%H-%M-%S")


def _coerce(value: str):
    if value == "-" or value == "":
        return None
    try:
        f = float(value)
    except ValueError:
        return value
    if f.is_integer():
        return int(f)
    return f


def _parse_header(line: str) -> list[str]:
    marker = "#fields"
    idx = line.find(marker)
    raw = line[idx + len(marker):].strip()
    return raw.split("\t")


def _columns_from_closest_header(lines: list[str], start: int) -> Optional[list[str]]:
    for i in range(start, -1, -1):
        line = lines[i]
        if line.startswith("#fields"):
            return _parse_header(line)
    return None


def load_conn_log(path: str | Path) -> list[Connection]:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Zeek log not found: {path}")

    text = path.read_text(encoding="utf-8", errors="replace")
    return list(iter_conn_log(text))


def iter_conn_log(text: str) -> Iterator[Connection]:
    lines = text.splitlines()
    columns: Optional[list[str]] = None

    for i, raw in enumerate(lines):
        if not raw:
            continue
        if raw.startswith("#"):
            if raw.startswith("#fields"):
                columns = _parse_header(raw)
            continue
        if columns is None:
            columns = _columns_from_closest_header(lines, i)
            if columns is None:
                continue

        fields = raw.split("\t")
        if len(fields) < len(columns):
            fields += ["-"] * (len(columns) - len(fields))
        record = {col: _coerce(val) for col, val in zip(columns, fields)}

        try:
            conn = _record_to_connection(record)
        except (KeyError, TypeError, ValueError):
            continue
        yield conn


def _record_to_connection(r: dict) -> Connection:
    def _f(name) -> Optional[float]:
        v = r.get(name)
        return float(v) if isinstance(v, (int, float)) else None

    def _i(name) -> int:
        v = r.get(name)
        return int(v) if isinstance(v, (int, float)) else 0

    return Connection(
        ts=float(r["ts"]),
        uid=str(r.get("uid", "")),
        src_ip=str(r["id.orig_h"]),
        src_port=_i("id.orig_p"),
        dst_ip=str(r["id.resp_h"]),
        dst_port=_i("id.resp_p"),
        proto=str(r.get("proto", "tcp")),
        service=r.get("service") if isinstance(r.get("service"), str) else None,
        duration=_f("duration"),
        orig_bytes=_f("orig_bytes"),
        resp_bytes=_f("resp_bytes"),
        conn_state=r.get("conn_state") if isinstance(r.get("conn_state"), str) else None,
    )
