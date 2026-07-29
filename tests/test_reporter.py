import json
from pathlib import Path

from c2_traffic_analyzer import DetectionConfig, detect_beacons, load_conn_log
from c2_traffic_analyzer.attack_mapping import annotate
from c2_traffic_analyzer.reporter import (
    render_csv,
    render_json,
    render_table,
    write_outputs,
)


def _findings(sample_conn_log):
    conns = load_conn_log(sample_conn_log)
    return annotate(detect_beacons(conns, DetectionConfig(min_beacon_score=0.6)))


def test_render_table_non_empty(sample_conn_log):
    out = render_table(_findings(sample_conn_log))
    assert "192.168.56.33" in out
    assert "beacon_score" in out or "beacon" in out.lower() or "7101" in out


def test_render_json_valid(sample_conn_log):
    data = json.loads(render_json(_findings(sample_conn_log)))
    assert isinstance(data, list)
    assert any(d["dst_port"] == 7101 for d in data)
    assert all(d["techniques"] for d in data)


def test_render_csv_has_header(sample_conn_log):
    out = render_csv(_findings(sample_conn_log))
    assert "beacon_score" in out.splitlines()[0]
    assert len(out.splitlines()) >= 2


def test_render_empty_findings():
    assert "No beaconing" in render_table([])


def test_write_outputs_creates_files(sample_conn_log, tmp_path: Path):
    written = write_outputs(_findings(sample_conn_log), tmp_path)
    assert written["json"].exists()
    assert written["csv"].exists()
    json.loads(written["json"].read_text())
