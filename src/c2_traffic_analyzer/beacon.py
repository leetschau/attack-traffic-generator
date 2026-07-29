from __future__ import annotations

import statistics
from collections import defaultdict
from typing import Iterable

from .models import BeaconFinding, ChannelKey, Connection, DetectionConfig
from .scoring import intervals, jitter_ratio, regularity_score


def group_connections(conns: Iterable[Connection]) -> dict[ChannelKey, list[Connection]]:
    grouped: dict[ChannelKey, list[Connection]] = defaultdict(list)
    for c in conns:
        key = ChannelKey(c.src_ip, c.dst_ip, c.dst_port, c.proto)
        grouped[key].append(c)
    for bucket in grouped.values():
        bucket.sort(key=lambda c: c.ts)
    return grouped


def _drop_outlier_gap(deltas: list[float]) -> list[float]:
    if len(deltas) <= 2:
        return deltas
    largest = max(deltas)
    deltas.remove(largest)
    return deltas


def _channel_scores(bucket: list[Connection]) -> tuple[float, float, float]:
    timestamps = [c.ts for c in bucket]
    delta_seq = _drop_outlier_gap(intervals(timestamps))

    ts_score = regularity_score(delta_seq) if delta_seq else 0.0

    orig_sizes = [c.orig_bytes for c in bucket if c.orig_bytes is not None]
    resp_sizes = [c.resp_bytes for c in bucket if c.resp_bytes is not None]
    size_pool = resp_sizes or orig_sizes
    ds_score = regularity_score(size_pool) if size_pool else 0.0

    durations = [c.duration for c in bucket if c.duration is not None]
    duration_score = regularity_score(durations) if durations else 0.0

    return ts_score, ds_score, duration_score


def score_channel(bucket: list[Connection]) -> BeaconFinding:
    ts_score, ds_score, duration_score = _channel_scores(bucket)
    beacon_score = round((ts_score + ds_score + duration_score) / 3.0, 4)

    timestamps = [c.ts for c in bucket]
    delta_seq = intervals(timestamps)
    interval_mean = statistics.fmean(delta_seq) if delta_seq else 0.0
    interval_jitter = jitter_ratio(delta_seq)

    first = bucket[0]
    orig_bytes_mean = statistics.fmean(
        [c.orig_bytes for c in bucket if c.orig_bytes is not None]
    ) if any(c.orig_bytes is not None for c in bucket) else None
    resp_bytes_mean = statistics.fmean(
        [c.resp_bytes for c in bucket if c.resp_bytes is not None]
    ) if any(c.resp_bytes is not None for c in bucket) else None

    return BeaconFinding(
        src_ip=first.src_ip,
        dst_ip=first.dst_ip,
        dst_port=first.dst_port,
        proto=first.proto,
        service=first.service,
        connection_count=len(bucket),
        timespan_seconds=max(timestamps) - min(timestamps),
        ts_score=round(ts_score, 4),
        ds_score=round(ds_score, 4),
        duration_score=round(duration_score, 4),
        beacon_score=beacon_score,
        interval_mean=round(interval_mean, 4),
        interval_jitter=round(interval_jitter, 4),
        orig_bytes_mean=orig_bytes_mean,
        resp_bytes_mean=resp_bytes_mean,
    )


def detect_beacons(
    conns: Iterable[Connection],
    config: DetectionConfig | None = None,
) -> list[BeaconFinding]:
    cfg = config or DetectionConfig()
    grouped = group_connections(conns)
    findings: list[BeaconFinding] = []

    for key, bucket in grouped.items():
        if len(bucket) < cfg.min_connections:
            continue
        timespan = max(c.ts for c in bucket) - min(c.ts for c in bucket)
        if timespan < cfg.min_timespan_seconds:
            continue
        if cfg.skip_internal_pairs and _is_internal_pair(key.src_ip, key.dst_ip):
            continue
        if cfg.trusted_dst_ports and key.dst_port in cfg.trusted_dst_ports:
            continue

        finding = score_channel(bucket)
        if (
            finding.beacon_score >= cfg.min_beacon_score
            and finding.ts_score >= cfg.min_ts_score
        ):
            findings.append(finding)

    findings.sort(key=lambda f: f.beacon_score, reverse=True)
    return findings


def _is_internal_pair(src: str, dst: str) -> bool:
    for ip in (src, dst):
        if ip.startswith(("10.", "192.168.", "172.")):
            return True
    return False
