from c2_traffic_analyzer import iter_conn_log, load_conn_log


def test_load_conn_log_returns_records(sample_conn_log):
    conns = load_conn_log(sample_conn_log)
    assert len(conns) > 0
    channels = {(c.src_ip, c.dst_ip, c.dst_port) for c in conns}
    assert ("192.168.56.41", "192.168.56.33", 7101) in channels
    assert ("192.168.56.44", "192.168.56.33", 7202) in channels
    assert ("192.168.56.51", "93.184.216.34", 80) in channels


def test_records_have_parsed_types(sample_log_text):
    conns = list(iter_conn_log(sample_log_text))
    first = conns[0]
    assert isinstance(first.ts, float)
    assert isinstance(first.src_port, int)
    assert isinstance(first.dst_port, int)
    assert first.proto == "tcp"


def test_dash_fields_become_none(sample_log_text):
    conns = list(iter_conn_log(sample_log_text))
    tcp_no_service = [c for c in conns if c.dst_port == 7101][0]
    assert tcp_no_service.service is None


def test_missing_file_raises(tmp_path):
    import pytest

    with pytest.raises(FileNotFoundError):
        load_conn_log(tmp_path / "nope.log")
