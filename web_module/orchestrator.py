
import time
from datetime import datetime

from toolkitTCU.web_module.scanners import http_headers
from toolkitTCU.web_module.scanners import ssl_tls
from toolkitTCU.web_module.scanners import exposed_files
from toolkitTCU.web_module.scanners import document_metadata
from toolkitTCU.web_module.scanners import additional_checks

from toolkitTCU.web_module.utils.model import (
    create_base_report,
    count_by_severity,
    VALID_SEVERITIES,
)
from toolkitTCU.web_module.utils.logger import get_logger

SCANNER_HEADERS = "http_headers"
SCANNER_SSL = "ssl_tls"
SCANNER_FILES = "exposed_files"
SCANNER_METADATA = "document_metadata"
SCANNER_ADDITIONAL = "additional_checks"

AVAILABLE_SCANNERS = [
    SCANNER_HEADERS,
    SCANNER_SSL,
    SCANNER_FILES,
    SCANNER_METADATA,
    SCANNER_ADDITIONAL,
]

SCANNER_DISPLAY_NAMES = {
    SCANNER_HEADERS: "Verificador de Headers HTTP",
    SCANNER_SSL: "Auditor SSL/TLS",
    SCANNER_FILES: "Detector de Archivos Expuestos",
    SCANNER_METADATA: "Analizador de Metadatos en Documentos",
    SCANNER_ADDITIONAL: "Funcionalidades Adicionales (Cookies, robots.txt, Tecnologias)",
}

def normalize_url(url):
    if not url:
        return None
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

def calculate_global_score(scanner_results):
    scores = [
        r["score"]
        for r in scanner_results.values()
        if r["status"] in ("completed", "partial")
    ]
    if not scores:
        return 0
    return round(sum(scores) / len(scores))

def run_analysis(
    url,
    scanners_to_run=None,
    timeout=15,
    max_file_paths=None,
    max_documents=10,
    progress_callback=None,
):
    log = get_logger()
    total_start = time.time()

    normalized_url = normalize_url(url)
    if not normalized_url:
        raise ValueError("URL invalida o vacia.")

    if scanners_to_run is None:
        scanners_to_run = list(AVAILABLE_SCANNERS)

    invalid = [s for s in scanners_to_run if s not in AVAILABLE_SCANNERS]
    if invalid:
        raise ValueError(f"Scanners invalidos: {invalid}")

    log.info("=" * 70)
    log.info(f"INICIANDO ANALISIS DEL DOMINIO: {normalized_url}")
    log.info(f"Scanners a ejecutar: {', '.join(scanners_to_run)}")
    log.info("=" * 70)

    report = create_base_report(normalized_url)

    def run_headers():
        return http_headers.run(normalized_url, timeout=timeout)

    def run_ssl():
        return ssl_tls.run(normalized_url, timeout=timeout)

    def run_files():
        return exposed_files.run(
            normalized_url,
            timeout=timeout,
            max_paths=max_file_paths,
        )

    def run_metadata():
        return document_metadata.run(
            normalized_url,
            max_documents=max_documents,
            timeout=timeout,
        )

    def run_additional():
        return additional_checks.run(normalized_url, timeout=timeout)

    runners = {
        SCANNER_HEADERS: run_headers,
        SCANNER_SSL: run_ssl,
        SCANNER_FILES: run_files,
        SCANNER_METADATA: run_metadata,
        SCANNER_ADDITIONAL: run_additional,
    }

    for name in scanners_to_run:
        if progress_callback:
            progress_callback(name, "running")

        try:
            scanner_result = runners[name]()
        except Exception as e:
            log.error(f"Error inesperado en scanner {name}: {e}")
            from toolkitTCU.web_module.utils.model import create_scanner_result, STATUS_FAILED
            scanner_result = create_scanner_result(name)
            scanner_result["status"] = STATUS_FAILED
            scanner_result["error_message"] = f"Error inesperado: {e}"

        report["scanners"][name] = scanner_result

        if progress_callback:
            progress_callback(name, scanner_result["status"])

    all_findings = []
    for r in report["scanners"].values():
        all_findings.extend(r["findings"])

    report["executive_summary"]["global_score"] = calculate_global_score(report["scanners"])
    report["executive_summary"]["total_findings"] = len(all_findings)
    report["executive_summary"]["severity_count"] = count_by_severity(all_findings)
    report["metadata"]["end_time"] = datetime.now().isoformat()
    report["metadata"]["duration_seconds"] = round(time.time() - total_start, 2)

    log.info("=" * 70)
    log.info(
        f"ANALISIS FINALIZADO - "
        f"Puntaje global: {report['executive_summary']['global_score']}/100 - "
        f"Hallazgos: {report['executive_summary']['total_findings']} - "
        f"Duracion: {report['metadata']['duration_seconds']}s"
    )
    log.info("=" * 70)

    return report

def get_sorted_findings(report):
    severity_order = {sev: i for i, sev in enumerate(VALID_SEVERITIES)}

    all_findings = []
    for scanner_id, result in report["scanners"].items():
        for finding in result["findings"]:
            finding_copy = dict(finding)
            finding_copy["_scanner"] = result["scanner"]
            all_findings.append(finding_copy)

    all_findings.sort(key=lambda f: severity_order.get(f["severity"], 99))
    return all_findings
