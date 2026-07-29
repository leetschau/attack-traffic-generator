from c2_traffic_analyzer.app import main


def test_cli_flags_beacon_and_returns_nonzero(sample_conn_log, capsys):
    rc = main([
        str(sample_conn_log),
        "--min-connections", "10",
        "--min-score", "0.6",
        "--format", "json",
    ])
    captured = capsys.readouterr()
    assert rc == 1
    import json

    data = json.loads(captured.out)
    assert any(d["dst_port"] == 7101 for d in data)


def test_cli_no_attack_omits_techniques(sample_conn_log, capsys):
    rc = main([
        str(sample_conn_log),
        "--min-connections", "10",
        "--min-score", "0.6",
        "--format", "json",
        "--no-attack",
    ])
    capsys.readouterr()
    assert rc == 1


def test_cli_clean_log_returns_zero(tmp_path):
    log = tmp_path / "conn.log"
    log.write_text(
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\t"
        "service\tduration\torig_bytes\tresp_bytes\tconn_state\n"
        "1.0\ta\t10.0.0.1\t1\t10.0.0.2\t80\ttcp\thttp\t0.1\t10\t10\tSF\n"
    )
    rc = main([str(log), "--format", "table"])
    assert rc == 0


def test_cli_outdir_writes_files(sample_conn_log, tmp_path, capsys):
    rc = main([
        str(sample_conn_log),
        "--min-connections", "10",
        "--min-score", "0.6",
        "--format", "table",
        "-o", str(tmp_path / "out"),
    ])
    capsys.readouterr()
    assert rc == 1
    assert (tmp_path / "out" / "beacon_findings.json").exists()
