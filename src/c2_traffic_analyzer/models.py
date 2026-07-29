from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


MISSING = None


@dataclass(frozen=True)
class Connection:
    ts: float
    uid: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str
    service: Optional[str]
    duration: Optional[float]
    orig_bytes: Optional[float]
    resp_bytes: Optional[float]
    conn_state: Optional[str]


@dataclass(frozen=True)
class ChannelKey:
    src_ip: str
    dst_ip: str
    dst_port: int
    proto: str


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic: str


@dataclass
class BeaconFinding:
    src_ip: str
    dst_ip: str
    dst_port: int
    proto: str
    service: Optional[str]

    connection_count: int
    timespan_seconds: float

    ts_score: float
    ds_score: float
    duration_score: float
    beacon_score: float

    interval_mean: float
    interval_jitter: float
    orig_bytes_mean: float
    resp_bytes_mean: float

    techniques: list[Technique] = field(default_factory=list)

    @property
    def channel(self) -> ChannelKey:
        return ChannelKey(self.src_ip, self.dst_ip, self.dst_port, self.proto)

    def as_dict(self) -> dict:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "proto": self.proto,
            "service": self.service,
            "connection_count": self.connection_count,
            "timespan_seconds": round(self.timespan_seconds, 3),
            "ts_score": round(self.ts_score, 4),
            "ds_score": round(self.ds_score, 4),
            "duration_score": round(self.duration_score, 4),
            "beacon_score": round(self.beacon_score, 4),
            "interval_mean": round(self.interval_mean, 4),
            "interval_jitter": round(self.interval_jitter, 4),
            "orig_bytes_mean": round(self.orig_bytes_mean, 2) if self.orig_bytes_mean else None,
            "resp_bytes_mean": round(self.resp_bytes_mean, 2) if self.resp_bytes_mean else None,
            "techniques": [
                {"id": t.id, "name": t.name, "tactic": t.tactic} for t in self.techniques
            ],
        }


@dataclass(frozen=True)
class DetectionConfig:
    min_connections: int = 10
    min_beacon_score: float = 0.7
    min_ts_score: float = 0.5
    min_timespan_seconds: float = 30.0
    skip_internal_pairs: bool = False
    trusted_dst_ports: tuple[int, ...] = ()
