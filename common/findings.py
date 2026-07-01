
from datetime import datetime

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"

VALID_SEVERITIES = [
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFO,
]

SEVERITY_WEIGHTS = {
    SEVERITY_CRITICAL: 25,
    SEVERITY_HIGH: 15,
    SEVERITY_MEDIUM: 8,
    SEVERITY_LOW: 3,
    SEVERITY_INFO: 0,
}

MODULE_WEB = "web"
MODULE_NETWORK = "network"
MODULE_INTEGRITY = "integrity"

MODULE_DISPLAY_NAMES = {
    MODULE_WEB: "Análisis Web",
    MODULE_NETWORK: "Análisis de Red",
    MODULE_INTEGRITY: "Integridad de Archivos",
}

_SEVERITY_ALIASES = {
    "CRITICAL": SEVERITY_CRITICAL,
    "CRITICO": SEVERITY_CRITICAL,
    "HIGH": SEVERITY_HIGH,
    "ALTO": SEVERITY_HIGH,
    "MEDIUM": SEVERITY_MEDIUM,
    "MEDIO": SEVERITY_MEDIUM,
    "LOW": SEVERITY_LOW,
    "BAJO": SEVERITY_LOW,
    "INFO": SEVERITY_INFO,
    "INFORMATIVO": SEVERITY_INFO,
    "NONE": SEVERITY_INFO,
    "UNKNOWN": SEVERITY_INFO,
    "DESCONOCIDO": SEVERITY_INFO,
}

def normalize_severity(value):
    if value is None:
        return SEVERITY_INFO
    key = str(value).strip().upper()
    return _SEVERITY_ALIASES.get(key, SEVERITY_INFO)

def severity_from_cvss(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return SEVERITY_INFO
    if s >= 9.0:
        return SEVERITY_CRITICAL
    if s >= 7.0:
        return SEVERITY_HIGH
    if s >= 4.0:
        return SEVERITY_MEDIUM
    if s > 0.0:
        return SEVERITY_LOW
    return SEVERITY_INFO

def create_finding(
    module,
    finding_id,
    title,
    severity,
    category,
    description,
    recommendation="",
    evidence=None,
):
    return {
        "module": module,
        "id": finding_id,
        "title": title,
        "severity": normalize_severity(severity),
        "category": category,
        "description": description,
        "recommendation": recommendation,
        "evidence": evidence or {},
    }

def create_module_result(module, status="completed", error_message=None):
    return {
        "module": module,
        "display_name": MODULE_DISPLAY_NAMES.get(module, module),
        "status": status,
        "findings": [],
        "error_message": error_message,
        "summary": {},
    }

def count_by_severity(findings):
    counter = {sev: 0 for sev in VALID_SEVERITIES}
    for finding in findings:
        sev = finding.get("severity")
        if sev in counter:
            counter[sev] += 1
    return counter

def calculate_score(findings):
    score = 100
    for finding in findings:
        score -= SEVERITY_WEIGHTS.get(finding.get("severity"), 0)
    return max(0, score)

def sort_findings(findings):
    order = {sev: i for i, sev in enumerate(VALID_SEVERITIES)}
    return sorted(findings, key=lambda f: order.get(f.get("severity"), 99))

def create_unified_report():
    return {
        "metadata": {
            "generated_at": datetime.now().isoformat(),
            "toolkit_version": "1.0.0",
        },
        "executive_summary": {
            "global_score": 0,
            "total_findings": 0,
            "severity_count": {sev: 0 for sev in VALID_SEVERITIES},
            "modules_run": [],
        },
        "modules": {},
    }

def add_module_result(report, module_result):
    module = module_result["module"]
    report["modules"][module] = module_result

    all_findings = []
    for result in report["modules"].values():
        all_findings.extend(result["findings"])

    report["executive_summary"]["total_findings"] = len(all_findings)
    report["executive_summary"]["severity_count"] = count_by_severity(all_findings)
    report["executive_summary"]["global_score"] = calculate_score(all_findings)
    report["executive_summary"]["modules_run"] = list(report["modules"].keys())
    return report

def all_findings(report):
    findings = []
    for result in report["modules"].values():
        findings.extend(result["findings"])
    return sort_findings(findings)
