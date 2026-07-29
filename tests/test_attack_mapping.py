from c2_traffic_analyzer.attack_mapping import map_finding, technique_db
from c2_traffic_analyzer.models import BeaconFinding, Technique


def _finding(dst_port, proto="tcp", service=None, resp_bytes_mean=200.0, count=15):
    return BeaconFinding(
        src_ip="10.0.0.5", dst_ip="10.0.0.9", dst_port=dst_port, proto=proto,
        service=service, connection_count=count, timespan_seconds=600.0,
        ts_score=0.9, ds_score=0.9, duration_score=0.9, beacon_score=0.9,
        interval_mean=5.0, interval_jitter=0.01,
        orig_bytes_mean=120.0, resp_bytes_mean=resp_bytes_mean,
    )


def _ids(techniques):
    return {t.id for t in techniques}


def test_https_port_maps_to_web_and_encrypted():
    techs = map_finding(_finding(443, service="ssl"))
    assert "T1071.001" in _ids(techs)
    assert "T1573.002" in _ids(techs)


def test_non_standard_port_maps_to_t1571():
    techs = map_finding(_finding(7101))
    assert "T1571" in _ids(techs)


def test_standard_web_port_not_t1571():
    techs = map_finding(_finding(80, service="http"))
    assert "T1571" not in _ids(techs)
    assert "T1071.001" in _ids(techs)


def test_always_includes_parent_application_layer():
    techs = map_finding(_finding(7101))
    assert "T1071" in _ids(techs)


def test_large_resp_maps_to_tool_transfer():
    techs = map_finding(_finding(443, resp_bytes_mean=1024 * 1024))
    assert "T1105" in _ids(techs)


def test_technique_db_lookup():
    db = technique_db()
    assert isinstance(db["T1571"], Technique)
    assert db["T1071.001"].name
