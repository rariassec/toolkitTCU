
import pytest

from toolkitTCU.common import findings as F
from toolkitTCU.integration import web_facade, network_facade, integrity_facade
from toolkitTCU.network_module.core.scan_results import scan_results

@pytest.fixture(autouse=True)
def reset_scan_results():
    original = {k: list(v) if isinstance(v, list) else v for k, v in scan_results.items()}
    for k in scan_results:
        scan_results[k] = [] if isinstance(scan_results[k], list) else 0
    yield
    scan_results.update(original)

def test_web_facade_normaliza_reporte():
    fake = {
        "metadata": {"domain": "https://x.org", "duration_seconds": 1.0},
        "executive_summary": {"global_score": 80},
        "scanners": {"http_headers": {"scanner": "Headers", "findings": [
            {"id": "H1", "title": "falta hsts", "severity": "MEDIUM",
             "owasp_category": "A05", "accessible_description": "d",
             "recommendation": "r", "evidence": {}},
        ]}},
    }
    res = web_facade.build_module_result(fake)
    assert res["module"] == F.MODULE_WEB
    assert len(res["findings"]) == 1
    assert res["findings"][0]["severity"] == F.SEVERITY_MEDIUM

def test_network_facade_normaliza_scan_results():
    scan_results["vulnerabilities"] = [{
        "ip": "10.0.0.1", "port": 22, "service": "ssh", "version": "x",
        "vulnerabilities": [{"cve": "CVE-1", "severity": "HIGH", "score": 7.5}],
    }]
    scan_results["dns"] = [{
        "timestamp": "t", "type": "Directa", "value": "malo.tk",
        "resolved": "1.2.3.4", "ip_malicious": "Si", "suspicious": "Si",
    }]
    res = network_facade.build_module_result()
    assert res["module"] == F.MODULE_NETWORK
    severidades = {f["severity"] for f in res["findings"]}
    assert F.SEVERITY_HIGH in severidades
    assert res["summary"]["clasificacion"] in ("BAJO", "MEDIO", "ALTO", "CRITICO")

def test_network_facade_sin_datos():
    res = network_facade.build_module_result()
    assert res["findings"] == []
    assert res["status"] == "not_run"

def test_integrity_facade_desde_eventos(db_manager, tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("x")
    inode, device = db_manager.file_handler.extract_file_info(str(f))
    db_manager.insert_creation_event(inode, device, "h", str(f), "HIGH")
    res = integrity_facade.build_module_result(db_manager)
    assert res["module"] == F.MODULE_INTEGRITY
    assert len(res["findings"]) == 1
    assert res["findings"][0]["severity"] == F.SEVERITY_HIGH
