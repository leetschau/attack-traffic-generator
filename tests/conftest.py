from __future__ import annotations

import random
from pathlib import Path

import pytest


HEADER = (
    "#separator \\x09\n"
    "#set_separator	,\n"
    "#empty_field	(empty)\n"
    "#unset_field	-\n"
    "#path	conn\n"
    "#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	"
    "duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	"
    "missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	"
    "tunnel_parents\n"
    "#types	time	string	addr	port	addr	port	enum	string	interval	"
    "count	count	string	bool	bool	count	string	count	count	count	count	"
    "set[string]\n"
)


def _row(ts, src_h, src_p, dst_h, dst_p, proto, service, duration, ob, rb, state="SF"):
    uid = f"C{int(ts*1000):x}{dst_port_salt(dst_p)}"
    fields = [
        f"{ts:.6f}", uid, src_h, src_p, dst_h, dst_p, proto, service,
        f"{duration:.6f}", ob if ob is not None else "-", rb if rb is not None else "-",
        state, "T", "T", "0", "ShAdDaF", "5", "220", "5", "280", "-",
    ]
    return "\t".join(str(f) for f in fields)


def dst_port_salt(p):
    return f"{p:x}"


def build_sample_log(seed: int = 42) -> str:
    rnd = random.Random(seed)
    lines = [HEADER]
    base = 1_700_000_000.0

    for i in range(40):
        ts = base + i * 5.0 + rnd.uniform(-0.05, 0.05)
        lines.append(_row(ts, "192.168.56.41", 49152 + (i % 1000), "192.168.56.33", 7101, "tcp", "-", 0.02, 120, 210))

    for i in range(30):
        ts = base + i * 8.0 + rnd.uniform(-0.1, 0.1)
        lines.append(_row(ts, "192.168.56.44", 50000 + i, "192.168.56.33", 7202, "tcp", "http", 0.05, 200, 180))

    for i in range(12):
        ts = base + rnd.uniform(0, 600)
        rb = rnd.randint(2000, 45000)
        lines.append(_row(ts, "192.168.56.51", 60000 + i, "93.184.216.34", 80, "tcp", "http", rnd.uniform(0.1, 1.5), 400, rb))

    return "\n".join(lines) + "\n"


@pytest.fixture
def sample_log_text() -> str:
    return build_sample_log()


@pytest.fixture
def sample_conn_log(tmp_path: Path, sample_log_text: str) -> Path:
    p = tmp_path / "conn.log"
    p.write_text(sample_log_text, encoding="utf-8")
    return p
