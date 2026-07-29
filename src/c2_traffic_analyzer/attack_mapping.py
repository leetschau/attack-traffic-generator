from __future__ import annotations

from typing import Iterable

from .models import BeaconFinding, Technique


_TECHNIQUE_DB: dict[str, Technique] = {
    "T1071": Technique("T1071", "Application Layer Protocol", "command-and-control"),
    "T1071.001": Technique(
        "T1071.001", "Web Protocols", "command-and-control"
    ),
    "T1571": Technique("T1571", "Non-Standard Port", "command-and-control"),
    "T1573": Technique("T1573", "Encrypted Channel", "command-and-control"),
    "T1573.002": Technique(
        "T1573.002", "Asymmetric Cryptography", "command-and-control"
    ),
    "T1105": Technique("T1105", "Ingress Tool Transfer", "command-and-control"),
    "T1090": Technique("T1090", "Proxy", "command-and-control"),
    "T1090.001": Technique("T1090.001", "Internal Proxy", "command-and-control"),
    "T1041": Technique("T1041", "Exfiltration Over C2 Channel", "exfiltration"),
    "T1132": Technique("T1132", "Data Encoding", "command-and-control"),
    "T1098": Technique("T1098", "Account Manipulation", "persistence"),
}


WEB_PORTS = {80, 8080, 8000, 8443}
TLS_PORTS = {443}
ENC_PORTS = {443, 465, 636, 853, 989, 990, 993, 995, 8443}
COMMON_PORTS = {20, 21, 22, 23, 25, 53, 80, 110, 123, 143, 161, 389, 443, 445, 465, 587, 636, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080}


def map_finding(finding: BeaconFinding) -> list[Technique]:
    matched: list[Technique] = []
    seen: set[str] = set()

    def add(tid: str) -> None:
        if tid in seen:
            return
        tech = _TECHNIQUE_DB.get(tid)
        if tech:
            matched.append(tech)
            seen.add(tid)

    add("T1071")

    port = finding.dst_port
    service = (finding.service or "").lower()
    proto = finding.proto.lower()

    if service in {"http", "ssl", "https"} or port in WEB_PORTS or port in TLS_PORTS:
        add("T1071.001")
    if port in TLS_PORTS or service in {"ssl", "https"} or port in ENC_PORTS:
        add("T1573.002")
        add("T1573")
    if proto in {"tcp", "udp"} and port not in COMMON_PORTS:
        add("T1571")

    if finding.resp_bytes_mean is not None and finding.resp_bytes_mean > 1024 * 512:
        add("T1105")
    if finding.connection_count >= 20:
        add("T1132")

    return matched


def annotate(findings: Iterable[BeaconFinding]) -> list[BeaconFinding]:
    for f in findings:
        f.techniques = map_finding(f)
    return list(findings)


def technique_db() -> dict[str, Technique]:
    return dict(_TECHNIQUE_DB)
