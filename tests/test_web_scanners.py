
from toolkitTCU.web_module.scanners import http_headers as HH
from toolkitTCU.web_module.scanners import ssl_tls as SSL
from toolkitTCU.web_module.utils import model as M

def test_hsts_ausente_genera_hallazgo_alto():
    finding = HH.evaluate_hsts({})
    assert finding is not None
    assert finding["severity"] == M.SEVERITY_HIGH
    assert finding["evidence"]["header_present"] is False

def test_hsts_presente_no_es_critico():
    finding = HH.evaluate_hsts(
        {"Strict-Transport-Security": "max-age=31536000; includeSubDomains"}
    )
    assert finding is None or finding["severity"] in (
        M.SEVERITY_INFO, M.SEVERITY_LOW, M.SEVERITY_MEDIUM,
    )

def test_csp_ausente_genera_hallazgo():
    finding = HH.evaluate_csp({})
    assert finding is not None
    assert finding["severity"] in (
        M.SEVERITY_LOW, M.SEVERITY_MEDIUM, M.SEVERITY_HIGH,
    )

def test_x_frame_options_ausente_genera_hallazgo():
    finding = HH.evaluate_x_frame_options({})
    assert finding is not None

def test_extract_host_port():
    assert SSL.extract_host_port("https://ejemplo.org") == ("ejemplo.org", 443)
    assert SSL.extract_host_port("http://ejemplo.org") == ("ejemplo.org", 80)
    assert SSL.extract_host_port("https://ejemplo.org:8443")[1] == 8443

def test_evaluate_robot_con_tls_antiguo():
    finding = SSL.evaluate_robot({"TLSv1.0": True})
    assert finding is not None

def test_evaluate_robot_sin_tls_antiguo():
    assert SSL.evaluate_robot({"TLSv1.2": True, "TLSv1.3": True}) is None
