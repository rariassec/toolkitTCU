
import os

os.environ.setdefault("MPLBACKEND", "Agg")

from flask import Flask, jsonify, render_template, request, send_from_directory

from toolkitTCU.webapp.jobs import jobs
from toolkitTCU.webapp.services import web_service
from toolkitTCU.webapp.services import network_service
from toolkitTCU.webapp.services import integrity_service

from toolkitTCU.common import findings as F
from toolkitTCU.common.reports import save_unified_report, REPORTS_DIR
from toolkitTCU.integration import network_facade, integrity_facade, web_facade

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
GRAPHS_DIR = os.path.join(BASE_DIR, "static", "graphs")

app = Flask(__name__)

def ok(data=None, **extra):
    payload = {"ok": True}
    if data is not None:
        payload["data"] = data
    payload.update(extra)
    return jsonify(payload)

def fail(message, code=400):
    return jsonify({"ok": False, "error": str(message)}), code

def body():
    return request.get_json(silent=True) or {}

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/jobs/<job_id>")
def job_status(job_id):
    job = jobs.get(job_id)
    if not job:
        return fail("Tarea no encontrada.", 404)
    return ok(job.to_dict())

@app.route("/api/web/scanners")
def web_scanners():
    return ok(web_service.available_scanners())

@app.route("/api/web/scan", methods=["POST"])
def web_scan():
    data = body()
    url = data.get("url", "")
    scanners = data.get("scanners") or None
    timeout = int(data.get("timeout", 15) or 15)
    max_documents = int(data.get("max_documents", 10) or 10)
    if not url.strip():
        return fail("Debe indicar una URL o dominio.")
    job = jobs.submit(
        "web", f"Analisis web de {url}",
        web_service.run_web_analysis, url, scanners, timeout, max_documents)
    return ok(job.to_dict())

@app.route("/api/network/state")
def network_state():
    return ok(network_service.state_summary())

@app.route("/api/network/resolve", methods=["POST"])
def network_resolve():
    try:
        scan_target, original, info = network_service.resolve_objective(body().get("target", ""))
        return ok({"scan_target": scan_target, "original": original, "info": info})
    except ValueError as e:
        return fail(e)

@app.route("/api/network/tcp", methods=["POST"])
def network_tcp():
    data = body()
    job = jobs.submit("network", f"Escaneo TCP de {data.get('target')}",
                      network_service.tcp_scan, data.get("target", ""),
                      data.get("depth", "quick"))
    return ok(job.to_dict())

@app.route("/api/network/udp", methods=["POST"])
def network_udp():
    data = body()
    job = jobs.submit("network", f"Escaneo UDP de {data.get('target')}",
                      network_service.udp_scan, data.get("target", ""),
                      data.get("depth", "quick"))
    return ok(job.to_dict())

@app.route("/api/network/custom", methods=["POST"])
def network_custom():
    data = body()
    job = jobs.submit("network", f"Escaneo personalizado de {data.get('target')}",
                      network_service.custom_scan, data.get("target", ""),
                      data.get("ports", "1-1024"), data.get("options", {}))
    return ok(job.to_dict())

@app.route("/api/network/vulnerabilities", methods=["POST"])
def network_vulns():
    data = body()
    job = jobs.submit("network", "Deteccion de servicios vulnerables",
                      network_service.vulnerability_scan, data.get("protocol", "both"))
    return ok(job.to_dict())

@app.route("/api/network/dns", methods=["POST"])
def network_dns():
    data = body()
    job = jobs.submit("network", f"Analisis DNS de {data.get('value')}",
                      network_service.dns_analysis, data.get("value", ""),
                      data.get("mode", "auto"))
    return ok(job.to_dict())

@app.route("/api/network/suspicious", methods=["POST"])
def network_suspicious():
    data = body()
    duration = int(data.get("duration_seconds", 60) or 60)
    job = jobs.submit("network", "Deteccion de conexiones sospechosas",
                      network_service.suspicious_connections, duration,
                      data.get("analysis_type", "BASICO"))
    return ok(job.to_dict())

@app.route("/api/network/risk")
def network_risk():
    try:
        return ok(network_service.risk_summary())
    except ValueError as e:
        return fail(e)

@app.route("/api/network/report", methods=["POST"])
def network_report():
    try:
        return ok(network_service.save_report())
    except ValueError as e:
        return fail(e)
    except Exception as e:
        return fail(e, 500)

@app.route("/api/network/keys")
def network_keys():
    return ok(network_service.get_api_keys())

@app.route("/api/network/keys", methods=["POST"])
def network_keys_set():
    data = body()
    try:
        return ok(network_service.set_api_key(data.get("provider"), data.get("key")))
    except ValueError as e:
        return fail(e)

@app.route("/api/network/keys", methods=["DELETE"])
def network_keys_delete():
    data = body()
    try:
        return ok(network_service.delete_api_key(data.get("provider")))
    except ValueError as e:
        return fail(e)

@app.route("/api/integrity/status")
def integrity_status():
    try:
        return ok(integrity_service.status_summary())
    except Exception as e:
        return fail(e, 500)

@app.route("/api/integrity/events")
def integrity_events():
    return ok(integrity_service.list_events())

@app.route("/api/integrity/changes")
def integrity_changes():
    return ok(integrity_service.list_changes())

@app.route("/api/integrity/paths")
def integrity_paths():
    return ok(integrity_service.list_monitored_paths())

@app.route("/api/integrity/store", methods=["POST"])
def integrity_store():
    data = body()
    try:
        return ok(integrity_service.store_hash(data.get("path", ""),
                                                data.get("algorithm", "sha256")))
    except ValueError as e:
        return fail(e)

@app.route("/api/integrity/detect", methods=["POST"])
def integrity_detect():
    data = body()
    job = jobs.submit("integrity", f"Deteccion manual en {data.get('path')}",
                      integrity_service.manual_detection,
                      data.get("path", ""), data.get("options", {}))
    return ok(job.to_dict())

@app.route("/api/integrity/monitor")
def integrity_monitor_status():
    try:
        return ok(integrity_service.monitoring_status())
    except Exception as e:
        return fail(e, 500)

@app.route("/api/integrity/monitor/start", methods=["POST"])
def integrity_monitor_start():
    try:
        return ok(integrity_service.start_monitoring())
    except ValueError as e:
        return fail(e)
    except Exception as e:
        return fail(e, 500)

@app.route("/api/integrity/monitor/stop", methods=["POST"])
def integrity_monitor_stop():
    try:
        return ok(integrity_service.stop_monitoring())
    except Exception as e:
        return fail(e, 500)

@app.route("/api/integrity/report", methods=["POST"])
def integrity_report():
    try:
        return ok(integrity_service.generate_report())
    except ValueError as e:
        return fail(e)
    except Exception as e:
        return fail(e, 500)

@app.route("/api/integrity/graphs", methods=["POST"])
def integrity_graphs():
    try:
        files = integrity_service.generate_graphs(GRAPHS_DIR)
        urls = {k: (f"/static/graphs/{v}" if v else None) for k, v in files.items()}
        return ok(urls)
    except Exception as e:
        return fail(e, 500)

@app.route("/api/integrity/config")
def integrity_config_get():
    return ok(integrity_service.get_config())

@app.route("/api/integrity/config", methods=["POST"])
def integrity_config_set():
    data = body()
    try:
        return ok(integrity_service.update_config(
            data.get("paths", []), data.get("recursive", True),
            data.get("algorithm", "sha256"), data.get("scan_interval", 10)))
    except Exception as e:
        return fail(e)

@app.route("/api/integrity/email", methods=["POST"])
def integrity_email():
    data = body()
    try:
        return ok(integrity_service.configure_email(
            data.get("sender"), data.get("password"), data.get("receiver")))
    except ValueError as e:
        return fail(e)

def _build_unified_report():
    report = F.create_unified_report()
    try:
        net = network_facade.build_module_result()
        if net and net.get("findings"):
            F.add_module_result(report, net)
    except Exception:
        pass
    try:
        integ = integrity_facade.build_module_result()
        if integ:
            F.add_module_result(report, integ)
    except Exception:
        pass
    try:
        web = web_facade.get_last_result()
        if web:
            F.add_module_result(report, web)
    except Exception:
        pass
    return report

@app.route("/api/unified")
def unified_report():
    report = _build_unified_report()
    findings = F.all_findings(report)
    return ok({"report": report, "findings": findings})

@app.route("/api/unified/save", methods=["POST"])
def unified_save():
    report = _build_unified_report()
    try:
        json_path, pdf_path = save_unified_report(report)
        return ok({"json": os.path.basename(json_path),
                   "pdf": os.path.basename(pdf_path)})
    except Exception as e:
        return fail(e, 500)

@app.route("/api/reports")
def list_reports():
    if not os.path.isdir(REPORTS_DIR):
        return ok([])
    items = []
    for name in sorted(os.listdir(REPORTS_DIR), reverse=True):
        full = os.path.join(REPORTS_DIR, name)
        if os.path.isfile(full):
            items.append({"name": name, "size": os.path.getsize(full)})
    return ok(items)

@app.route("/reports/<path:name>")
def download_report(name):
    return send_from_directory(REPORTS_DIR, name, as_attachment=True)

def main():
    host = os.environ.get("TCU_WEB_HOST", "127.0.0.1")
    port = int(os.environ.get("TCU_WEB_PORT", "5000"))
    debug = os.environ.get("TCU_WEB_DEBUG", "0") == "1"
    print("=" * 60)
    print(" TOOLKIT TCU - INTERFAZ WEB")
    print(f" Abriendo en: http://{host}:{port}")
    print("=" * 60)
    app.run(host=host, port=port, debug=debug, threaded=True)

if __name__ == "__main__":
    main()
