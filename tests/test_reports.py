
import os

import pytest

from toolkitTCU.common import findings as F
from toolkitTCU.common import reports as R

@pytest.fixture
def reports_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(R, "REPORTS_DIR", str(tmp_path))
    return str(tmp_path)

def _unified_report():
    rep = F.create_unified_report()
    mr = F.create_module_result(F.MODULE_WEB)
    mr["findings"] = [
        F.create_finding(F.MODULE_WEB, "W1", "falta hsts", "HIGH", "headers", "desc", "rec"),
    ]
    F.add_module_result(rep, mr)
    return rep

def test_save_json_report(reports_dir):
    path = R.save_json_report(_unified_report(), "test")
    assert path.endswith(".json")
    assert os.path.exists(path)

def test_save_pdf_report(reports_dir):
    path = R.save_pdf_report(_unified_report(), "test", "Titulo de prueba")
    assert path.endswith(".pdf")
    assert os.path.getsize(path) > 0

def test_save_module_report_genera_json_y_pdf(reports_dir):
    mr = F.create_module_result(F.MODULE_NETWORK)
    mr["findings"] = [
        F.create_finding(F.MODULE_NETWORK, "N1", "cve", "CRITICAL", "vuln", "desc", "rec"),
    ]
    json_path, pdf_path = R.save_module_report(mr, "test_red", "Reporte de Red")
    assert os.path.exists(json_path)
    assert os.path.exists(pdf_path)

def test_save_unified_report_genera_json_y_pdf(reports_dir):
    json_path, pdf_path = R.save_unified_report(_unified_report(), "test_unif", "Unificado")
    assert os.path.exists(json_path)
    assert os.path.exists(pdf_path)
