
import pytest

from toolkitTCU.web_module import orchestrator as O

def test_normalize_url_agrega_esquema():
    assert O.normalize_url("ejemplo.org") == "https://ejemplo.org"
    assert O.normalize_url("http://ejemplo.org") == "http://ejemplo.org"
    assert O.normalize_url("  https://x.org  ") == "https://x.org"

def test_normalize_url_vacia():
    assert O.normalize_url("") is None
    assert O.normalize_url(None) is None

def test_calculate_global_score_promedia_completados():
    scanners = {
        "a": {"status": "completed", "score": 80},
        "b": {"status": "completed", "score": 60},
        "c": {"status": "failed", "score": 0},
    }
    assert O.calculate_global_score(scanners) == 70

def test_calculate_global_score_sin_datos():
    assert O.calculate_global_score({}) == 0

def test_run_analysis_url_invalida():
    with pytest.raises(ValueError):
        O.run_analysis("")

def test_run_analysis_scanner_invalido():
    with pytest.raises(ValueError):
        O.run_analysis("ejemplo.org", scanners_to_run=["no_existe"])
