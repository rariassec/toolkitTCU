
from toolkitTCU.common import findings as F
from toolkitTCU.common.reports import save_module_report
from toolkitTCU.web_module import orchestrator

_LAST_RESULT = None

def get_last_result():
    return _LAST_RESULT

def save_reports(report):
    global _LAST_RESULT
    module_result = build_module_result(report)
    _LAST_RESULT = module_result
    try:
        json_path, pdf_path = save_module_report(
            module_result, "reporte_web", "Reporte de Análisis Web"
        )
        print(f"\n[+] Reporte web guardado:")
        print(f"    JSON: {json_path}")
        print(f"    PDF : {pdf_path}")
    except Exception as error:
        print(f"\n[-] No se pudo guardar el reporte web: {error}")
    return module_result

def _to_common_findings(report):
    out = []
    for scanner_id, result in report.get("scanners", {}).items():
        scanner_name = result.get("scanner", scanner_id)
        for finding in result.get("findings", []):
            out.append(F.create_finding(
                module=F.MODULE_WEB,
                finding_id=finding.get("id", "WEB"),
                title=finding.get("title", ""),
                severity=finding.get("severity"),
                category=finding.get("owasp_category") or scanner_name,
                description=finding.get("accessible_description")
                or finding.get("technical_description", ""),
                recommendation=finding.get("recommendation", ""),
                evidence=dict(finding.get("evidence", {}), _scanner=scanner_name),
            ))
    return out

def build_module_result(report):
    result = F.create_module_result(F.MODULE_WEB)
    result["findings"] = _to_common_findings(report)
    summary = report.get("executive_summary", {})
    result["summary"] = {
        "dominio": report.get("metadata", {}).get("domain"),
        "puntaje_web_0_100": summary.get("global_score"),
        "duracion_s": report.get("metadata", {}).get("duration_seconds"),
    }
    return result

def run_analysis(url, scanners_to_run=None, **kwargs):
    report = orchestrator.run_analysis(url, scanners_to_run=scanners_to_run, **kwargs)
    return build_module_result(report)

def run_interactive():
    from toolkitTCU.web_module import cli
    report = cli.run_interactive_analysis()
    if report is None:
        return None
    return save_reports(report)
    return None
