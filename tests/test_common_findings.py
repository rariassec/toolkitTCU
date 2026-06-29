
from toolkitTCU.common import findings as F

def test_normalize_severity_espanol_a_canonico():
    assert F.normalize_severity("ALTO") == F.SEVERITY_HIGH
    assert F.normalize_severity("critico") == F.SEVERITY_CRITICAL
    assert F.normalize_severity("Medio") == F.SEVERITY_MEDIUM
    assert F.normalize_severity("bajo") == F.SEVERITY_LOW

def test_normalize_severity_desconocida_y_none():
    assert F.normalize_severity("xyz") == F.SEVERITY_INFO
    assert F.normalize_severity(None) == F.SEVERITY_INFO

def test_severity_from_cvss_rangos():
    assert F.severity_from_cvss(9.5) == F.SEVERITY_CRITICAL
    assert F.severity_from_cvss(7.0) == F.SEVERITY_HIGH
    assert F.severity_from_cvss(4.0) == F.SEVERITY_MEDIUM
    assert F.severity_from_cvss(0.1) == F.SEVERITY_LOW
    assert F.severity_from_cvss(0) == F.SEVERITY_INFO
    assert F.severity_from_cvss("no-numero") == F.SEVERITY_INFO

def test_create_finding_normaliza_severidad():
    f = F.create_finding(F.MODULE_NETWORK, "ID1", "titulo", "ALTO", "cat", "desc")
    assert f["severity"] == F.SEVERITY_HIGH
    assert f["module"] == F.MODULE_NETWORK
    assert f["evidence"] == {}

def test_count_by_severity():
    fs = [
        {"severity": F.SEVERITY_HIGH},
        {"severity": F.SEVERITY_HIGH},
        {"severity": F.SEVERITY_LOW},
    ]
    c = F.count_by_severity(fs)
    assert c[F.SEVERITY_HIGH] == 2
    assert c[F.SEVERITY_LOW] == 1
    assert c[F.SEVERITY_CRITICAL] == 0

def test_calculate_score_resta_pesos():
    assert F.calculate_score([]) == 100
    assert F.calculate_score([{"severity": F.SEVERITY_CRITICAL}]) == 75
    muchos = [{"severity": F.SEVERITY_CRITICAL}] * 10
    assert F.calculate_score(muchos) == 0

def test_sort_findings_por_severidad():
    fs = [
        {"severity": F.SEVERITY_LOW},
        {"severity": F.SEVERITY_CRITICAL},
        {"severity": F.SEVERITY_MEDIUM},
    ]
    ordenados = F.sort_findings(fs)
    assert ordenados[0]["severity"] == F.SEVERITY_CRITICAL
    assert ordenados[-1]["severity"] == F.SEVERITY_LOW

def test_reporte_unificado_consolida_modulos():
    rep = F.create_unified_report()
    mr = F.create_module_result(F.MODULE_NETWORK)
    mr["findings"] = [
        F.create_finding(F.MODULE_NETWORK, "N1", "t", F.SEVERITY_HIGH, "c", "d"),
        F.create_finding(F.MODULE_NETWORK, "N2", "t", F.SEVERITY_LOW, "c", "d"),
    ]
    F.add_module_result(rep, mr)
    es = rep["executive_summary"]
    assert es["total_findings"] == 2
    assert es["severity_count"][F.SEVERITY_HIGH] == 1
    assert es["modules_run"] == [F.MODULE_NETWORK]
    assert 0 <= es["global_score"] <= 100
    assert len(F.all_findings(rep)) == 2
