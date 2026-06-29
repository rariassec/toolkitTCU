
import json
import time

import pytest

@pytest.fixture
def client():
    from toolkitTCU.webapp.app import app
    app.config.update(TESTING=True)
    return app.test_client()

@pytest.fixture
def isolated_fim_db(tmp_path, monkeypatch):
    import sys
    import toolkitTCU.integrity_module.core.DatabaseManager
    from toolkitTCU.webapp.services import integrity_service

    dbmod = sys.modules["toolkitTCU.integrity_module.core.DatabaseManager"]
    monkeypatch.setattr(dbmod, "DB_PATH", str(tmp_path / "hashes.db"))
    monkeypatch.setattr(integrity_service, "_SYSTEM", None)
    yield integrity_service
    monkeypatch.setattr(integrity_service, "_SYSTEM", None)

def test_index_sirve_html(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b"Toolkit TCU" in r.data

@pytest.mark.parametrize("route", [
    "/api/web/scanners",
    "/api/network/state",
    "/api/network/keys",
    "/api/unified",
    "/api/reports",
])
def test_rutas_get_envelope_ok(client, route):
    r = client.get(route)
    assert r.status_code == 200
    data = r.get_json()
    assert data["ok"] is True
    assert "data" in data

def test_web_scanners_lista_los_cinco(client):
    data = client.get("/api/web/scanners").get_json()["data"]
    ids = {s["id"] for s in data}
    assert ids == {"http_headers", "ssl_tls", "exposed_files",
                   "document_metadata", "additional_checks"}

def test_job_inexistente_devuelve_404(client):
    r = client.get("/api/jobs/noexiste")
    assert r.status_code == 404
    assert r.get_json()["ok"] is False

def test_web_scan_sin_url_falla(client):
    r = client.post("/api/web/scan", json={"url": ""})
    assert r.status_code == 400
    assert r.get_json()["ok"] is False

def test_network_resolve_invalido(client):
    r = client.post("/api/network/resolve", json={"target": "no es valido!!"})
    assert r.status_code == 400
    assert r.get_json()["ok"] is False

def test_network_resolve_ip_valida(client):
    r = client.post("/api/network/resolve", json={"target": "127.0.0.1"})
    assert r.status_code == 200
    assert r.get_json()["data"]["scan_target"] == "127.0.0.1"

def test_network_risk_sin_datos(client, monkeypatch):
    from toolkitTCU.network_module.core.scan_results import scan_results
    for k in ("vulnerabilities", "dns", "suspicious_connections", "tcp", "udp"):
        monkeypatch.setitem(scan_results, k, [])
    r = client.get("/api/network/risk")
    assert r.status_code == 400
    assert r.get_json()["ok"] is False

def test_network_key_vacia_falla(client):
    r = client.post("/api/network/keys", json={"provider": "virustotal", "key": ""})
    assert r.status_code == 400

def test_job_exitoso_se_completa():
    from toolkitTCU.webapp.jobs import JobManager
    jm = JobManager()
    job = jm.submit("test", "suma", lambda a, b: a + b, 2, 3)
    for _ in range(50):
        if jm.get(job.id).status != "running":
            break
        time.sleep(0.02)
    done = jm.get(job.id)
    assert done.status == "done"
    assert done.result == 5
    assert done.finished_at is not None

def test_job_con_error_se_marca():
    from toolkitTCU.webapp.jobs import JobManager

    def boom():
        raise RuntimeError("fallo intencional")

    jm = JobManager()
    job = jm.submit("test", "boom", boom)
    for _ in range(50):
        if jm.get(job.id).status != "running":
            break
        time.sleep(0.02)
    done = jm.get(job.id)
    assert done.status == "error"
    assert "fallo intencional" in done.error

def test_web_service_run_normaliza_y_recuerda(monkeypatch):
    from toolkitTCU.webapp.services import web_service

    fake_report = {
        "metadata": {"domain": "https://demo.org", "duration_seconds": 1.2},
        "executive_summary": {"global_score": 80, "total_findings": 0,
                              "severity_count": {}},
        "scanners": {"http_headers": {"scanner": "Headers", "status": "completed",
                                      "findings": []}},
    }
    monkeypatch.setattr(web_service.orchestrator, "run_analysis",
                        lambda url, **kw: fake_report)
    saved = {}
    monkeypatch.setattr(web_service.web_facade, "save_reports",
                        lambda rep: saved.update(rep) or rep)

    out = web_service.run_web_analysis("demo.org", ["http_headers"])
    assert out["metadata"]["domain"] == "https://demo.org"
    assert "http_headers" in out["scanners"]
    assert saved

def test_web_scan_endpoint_flujo_completo(client, monkeypatch):
    from toolkitTCU.webapp.services import web_service
    fake_report = {
        "metadata": {"domain": "https://demo.org", "duration_seconds": 0.1},
        "executive_summary": {"global_score": 90, "total_findings": 1,
                              "severity_count": {"LOW": 1}},
        "scanners": {"ssl_tls": {"scanner": "SSL", "status": "completed", "findings": []}},
    }
    monkeypatch.setattr(web_service, "run_web_analysis", lambda *a, **k: fake_report)

    start = client.post("/api/web/scan", json={"url": "demo.org", "scanners": ["ssl_tls"]})
    jid = start.get_json()["data"]["id"]
    for _ in range(50):
        j = client.get(f"/api/jobs/{jid}").get_json()["data"]
        if j["status"] != "running":
            break
        time.sleep(0.05)
    assert j["status"] == "done"
    assert j["result"]["executive_summary"]["global_score"] == 90

def test_resolve_objective_rango():
    from toolkitTCU.webapp.services import network_service
    scan, original, info = network_service.resolve_objective("192.168.1.1-192.168.1.5")
    assert scan == original == "192.168.1.1-192.168.1.5"

def test_resolve_objective_vacio_falla():
    from toolkitTCU.webapp.services import network_service
    with pytest.raises(ValueError):
        network_service.resolve_objective("")

def test_api_keys_shape_y_mascara():
    from toolkitTCU.webapp.services import network_service
    assert network_service._mask("ABCDEFGHIJKL").startswith("ABCDEFGH")
    assert network_service._mask("ABCDEFGHIJKL").endswith("*")
    keys = network_service.get_api_keys()
    assert set(keys) == {"virustotal", "nvd"}
    assert "configured" in keys["virustotal"]

def test_vulnerability_scan_sin_escaneo_previo(monkeypatch):
    from toolkitTCU.webapp.services import network_service
    from toolkitTCU.network_module.core.scan_results import scan_results
    monkeypatch.setitem(scan_results, "tcp", [])
    monkeypatch.setitem(scan_results, "udp", [])
    with pytest.raises(ValueError):
        network_service.vulnerability_scan("both")

def test_integrity_status_shape(isolated_fim_db):
    s = isolated_fim_db.status_summary()
    assert set(s) >= {"monitored_files", "detected_changes", "system_state"}

def test_integrity_store_y_eventos(isolated_fim_db, tmp_path):
    f = tmp_path / "protegido.txt"
    f.write_text("contenido inicial")
    res = isolated_fim_db.store_hash(str(f), "sha256")
    assert res["stored"] is True
    res2 = isolated_fim_db.store_hash(str(f), "sha256")
    assert res2["stored"] is False
    eventos = isolated_fim_db.list_events()
    assert any(e["event_type"] == "CREATED" for e in eventos)

def test_integrity_store_ruta_inexistente(isolated_fim_db):
    with pytest.raises(ValueError):
        isolated_fim_db.store_hash("/ruta/que/no/existe/jamas", "sha256")

def test_integrity_detect_sin_cambios(isolated_fim_db, tmp_path):
    f = tmp_path / "estable.txt"
    f.write_text("sin cambios")
    isolated_fim_db.store_hash(str(f), "sha256")
    out = isolated_fim_db.manual_detection(str(f), {})
    assert out["outcome"] == "VERIFIED"

@pytest.fixture
def isolated_fim_full(tmp_path, monkeypatch):
    import sys
    import json
    from functools import partial
    import toolkitTCU.integrity_module.core.DatabaseManager
    from toolkitTCU.integrity_module.utils.LoadConfig import ConfigLoader
    from toolkitTCU.webapp.services import integrity_service

    watched = tmp_path / "watched"
    watched.mkdir()
    cfg_path = tmp_path / "config.json"
    cfg = {
        "watch": [{"paths": [str(watched)], "recursive": True}],
        "default_baseline": {"paths": [str(watched)]},
        "default_hashing_algorithm": "sha256",
        "backup": {"directory": str(tmp_path / "snap"), "interval_seconds": 60},
        "scan": {"interval_seconds": 60},
        "alerts": {"email_enabled": False, "desktop_notifications": False},
        "logging": {"directory": str(tmp_path / "logs")},
        "reports": {"individual": str(tmp_path / "rep"), "general": str(tmp_path / "rep")},
        "severity_levels": {"MODIFIED": {"MEDIUM": ["*"]}, "DELETED": {"MEDIUM": ["*"]},
                            "CREATED": {"LOW": ["*"]}},
        "default_severity": "MEDIUM",
    }
    cfg_path.write_text(json.dumps(cfg))

    dbmod = sys.modules["toolkitTCU.integrity_module.core.DatabaseManager"]
    monkeypatch.setattr(dbmod, "DB_PATH", str(tmp_path / "hashes.db"))
    monkeypatch.setattr(integrity_service, "DEFAULT_CONFIG_FILE", str(cfg_path))
    monkeypatch.setattr(integrity_service, "ConfigLoader",
                        partial(ConfigLoader, str(cfg_path)))
    monkeypatch.setattr(integrity_service, "_SYSTEM", None)
    yield integrity_service, watched
    try:
        integrity_service.stop_monitoring()
    except Exception:
        pass
    monkeypatch.setattr(integrity_service, "_SYSTEM", None)

def test_monitor_status_shape(isolated_fim_full):
    svc, _ = isolated_fim_full
    st = svc.monitoring_status()
    assert set(st) >= {"running", "watched", "email_enabled", "email_configured"}
    assert st["running"] is False

def test_monitor_start_sin_carpetas_validas(isolated_fim_full, monkeypatch):
    svc, _ = isolated_fim_full
    svc.update_config(["/ruta/que/no/existe/jamas"], True, "sha256", 60)
    with pytest.raises(ValueError):
        svc.start_monitoring()

def test_monitor_reinicia_solo_al_cambiar_config(isolated_fim_full, tmp_path):
    import time
    svc, watched = isolated_fim_full
    assert svc.start_monitoring()["running"] is True
    try:
        nueva = tmp_path / "watched2"
        nueva.mkdir()
        out = svc.update_config([str(watched), str(nueva)], True, "sha256", 60)
        assert out["monitoring"]["was_running"] is True
        assert out["monitoring"]["restarted"] is True
        assert svc.monitoring_status()["running"] is True

        (nueva / "x.txt").write_text("hola")
        deadline = time.time() + 8
        ok = False
        while time.time() < deadline:
            if any(e["file_path"].endswith("x.txt") for e in svc.list_events()):
                ok = True
                break
            time.sleep(0.3)
        assert ok
    finally:
        svc.stop_monitoring()

def test_monitor_detecta_creacion_en_tiempo_real(isolated_fim_full):
    import time
    svc, watched = isolated_fim_full
    st = svc.start_monitoring()
    assert st["running"] is True
    try:
        (watched / "nuevo.txt").write_text("contenido")
        deadline = time.time() + 8
        tipos = set()
        while time.time() < deadline:
            tipos = {e["event_type"] for e in svc.list_events()}
            if "CREATED" in tipos:
                break
            time.sleep(0.3)
        assert "CREATED" in tipos
    finally:
        svc.stop_monitoring()
    assert svc.monitoring_status()["running"] is False

def test_integrity_report_genera_json_y_pdf(isolated_fim_db, tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("contenido")
    isolated_fim_db.store_hash(str(f), "sha256")
    out = isolated_fim_db.generate_report()
    assert out["ok"] is True
    assert out["json"].endswith(".json")
    assert out["pdf"].endswith(".pdf")

def test_network_report_sin_datos_falla(client, monkeypatch):
    from toolkitTCU.network_module.core.scan_results import scan_results
    for k in ("tcp", "udp", "vulnerabilities", "dns", "suspicious_connections"):
        monkeypatch.setitem(scan_results, k, [])
    r = client.post("/api/network/report", json={})
    assert r.status_code == 400
    assert r.get_json()["ok"] is False

def test_network_report_genera_json_y_pdf(client, monkeypatch):
    from toolkitTCU.network_module.core.scan_results import scan_results
    monkeypatch.setitem(scan_results, "tcp", [
        {"ip": "127.0.0.1", "port": 22, "protocol": "TCP", "state": "open",
         "service": "ssh", "version": "OpenSSH 8.0"}])
    r = client.post("/api/network/report", json={})
    assert r.status_code == 200
    data = r.get_json()["data"]
    assert data["json"].endswith(".json") and data["pdf"].endswith(".pdf")

def test_config_default_sin_rutas_testing():
    import json, os
    base = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                        "integrity_module", "core", "config", "config.default.json")
    cfg = json.load(open(base, encoding="utf-8"))
    assert cfg["watch"][0]["paths"] == []
    assert cfg["default_baseline"]["paths"] == []

def test_unified_report_estructura(client):
    data = client.get("/api/unified").get_json()["data"]
    assert "report" in data and "findings" in data
    assert "executive_summary" in data["report"]

def test_static_assets_presentes_y_coherentes():
    import os
    base = os.path.join(os.path.dirname(os.path.dirname(__file__)), "webapp")
    for rel in ("static/css/styles.css", "static/js/app.js",
                "static/img/logo.svg", "templates/index.html"):
        assert os.path.isfile(os.path.join(base, rel)), f"falta {rel}"

    css = open(os.path.join(base, "static/css/styles.css"), encoding="utf-8").read()
    assert css.count("{") == css.count("}"), "llaves desbalanceadas en css"

    html = open(os.path.join(base, "templates/index.html"), encoding="utf-8").read()
    for page in ("dashboard", "web", "network", "integrity", "unified", "keys", "reports"):
        assert f'id="page-{page}"' in html, f"falta la seccion {page}"
