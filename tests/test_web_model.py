
import pytest

from toolkitTCU.web_module.utils import model as M

def test_create_finding_valido():
    f = M.create_finding(
        "WEB-1", "titulo", M.SEVERITY_HIGH, "A05",
        "descripcion accesible", "descripcion tecnica", "recomendacion",
    )
    assert f["severity"] == M.SEVERITY_HIGH
    assert f["evidence"] == {}
    assert f["resources"] == []

def test_create_finding_severidad_invalida():
    with pytest.raises(ValueError):
        M.create_finding(
            "WEB-2", "t", "SEVERIDAD_FALSA", "A05", "a", "b", "c",
        )

def test_calculate_score():
    assert M.calculate_score([]) == 100
    findings = [{"severity": M.SEVERITY_CRITICAL}, {"severity": M.SEVERITY_LOW}]
    assert M.calculate_score(findings) == 72

def test_count_by_severity():
    findings = [{"severity": M.SEVERITY_MEDIUM}, {"severity": M.SEVERITY_MEDIUM}]
    c = M.count_by_severity(findings)
    assert c[M.SEVERITY_MEDIUM] == 2

def test_create_base_report_estructura():
    rep = M.create_base_report("https://ejemplo.org")
    assert rep["metadata"]["domain"] == "https://ejemplo.org"
    assert rep["scanners"] == {}
    assert rep["executive_summary"]["global_score"] == 0
