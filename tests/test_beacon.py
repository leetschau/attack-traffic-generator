from c2_traffic_analyzer import DetectionConfig, detect_beacons, load_conn_log
from c2_traffic_analyzer.beacon import group_connections


def test_detects_known_beacon_channels(sample_conn_log):
    conns = load_conn_log(sample_conn_log)
    findings = detect_beacons(conns, DetectionConfig(min_connections=10, min_beacon_score=0.6))
    flagged = {(f.src_ip, f.dst_ip, f.dst_port) for f in findings}
    assert ("192.168.56.41", "192.168.56.33", 7101) in flagged
    assert ("192.168.56.44", "192.168.56.33", 7202) in flagged


def test_benign_channel_not_flagged(sample_conn_log):
    conns = load_conn_log(sample_conn_log)
    findings = detect_beacons(conns, DetectionConfig(min_connections=10, min_beacon_score=0.6))
    flagged = {(f.src_ip, f.dst_ip, f.dst_port) for f in findings}
    assert ("192.168.56.51", "93.184.216.34", 80) not in flagged


def test_min_connections_filters_noise(sample_conn_log):
    conns = load_conn_log(sample_conn_log)
    findings = detect_beacons(conns, DetectionConfig(min_connections=100))
    assert findings == []


def test_findings_sorted_by_score_desc(sample_conn_log):
    conns = load_conn_log(sample_conn_log)
    findings = detect_beacons(conns, DetectionConfig(min_connections=10, min_beacon_score=0.6))
    scores = [f.beacon_score for f in findings]
    assert scores == sorted(scores, reverse=True)


def test_group_connections_buckets_by_channel(sample_conn_log):
    conns = load_conn_log(sample_conn_log)
    grouped = group_connections(conns)
    assert len(grouped) >= 3
    for bucket in grouped.values():
        assert bucket == sorted(bucket, key=lambda c: c.ts)


def test_beacon_score_in_unit_range(sample_conn_log):
    conns = load_conn_log(sample_conn_log)
    findings = detect_beacons(conns, DetectionConfig(min_connections=10, min_beacon_score=0.0))
    for f in findings:
        assert 0.0 <= f.beacon_score <= 1.0
        assert 0.0 <= f.ts_score <= 1.0
