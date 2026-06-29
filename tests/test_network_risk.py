
import pytest

from toolkitTCU.network_module.core import risk_calculator as R
from toolkitTCU.network_module.core.scan_results import scan_results

@pytest.fixture(autouse=True)
def reset_scan_results():
    original = {k: list(v) if isinstance(v, list) else v for k, v in scan_results.items()}
    for k in scan_results:
        scan_results[k] = [] if isinstance(scan_results[k], list) else 0
    yield
    scan_results.update(original)

def test_classify_risk():
    assert R.classify_risk(9.5) == "CRITICO"
    assert R.classify_risk(7.5) == "ALTO"
    assert R.classify_risk(5.0) == "MEDIO"
    assert R.classify_risk(2.0) == "BAJO"

def test_calculate_impact_con_bonus():
    vuln = {"score": 7.0, "severity": "HIGH", "service": "ssh"}
    assert R.calculate_impact(vuln) == 10

def test_calculate_impact_score_invalido_no_crashea():
    vuln = {"score": "n/a", "severity": "LOW", "service": "http"}
    impacto = R.calculate_impact(vuln)
    assert isinstance(impacto, (int, float))

def test_get_all_vulnerabilities():
    scan_results["vulnerabilities"] = [{
        "ip": "10.0.0.1", "port": 22, "service": "ssh", "version": "x",
        "vulnerabilities": [{"cve": "CVE-1", "severity": "HIGH", "score": 7.5}],
    }]
    vulns = R.get_all_vulnerabilities()
    assert len(vulns) == 1
    assert vulns[0]["cve"] == "CVE-1"
    assert "impact" in vulns[0]

def test_build_risk_matrix():
    scan_results["vulnerabilities"] = [{
        "ip": "10.0.0.1", "port": 22, "service": "ssh", "version": "x",
        "vulnerabilities": [
            {"cve": "C1", "severity": "CRITICAL", "score": 9.5},
            {"cve": "C2", "severity": "LOW", "score": 2.0},
        ],
    }]
    matriz = R.build_risk_matrix()
    assert matriz["CRITICO"] == 1
    assert matriz["BAJO"] == 1

def test_dns_y_conexiones_score():
    scan_results["dns"] = [{"ip_malicious": "Si", "suspicious": "Si"}]
    scan_results["suspicious_connections"] = [{"risk": "ALTO"}]
    assert R.dns_risk_score() == 12
    assert R.suspicious_connections_score() == 8

def test_calculate_global_risk_acotado():
    scan_results["vulnerabilities"] = [{
        "ip": "10.0.0.1", "port": 22, "service": "ssh", "version": "x",
        "vulnerabilities": [{"cve": "C1", "severity": "CRITICAL", "score": 9.5}],
    }]
    riesgo = R.calculate_global_risk()
    assert 0 <= riesgo <= 10
