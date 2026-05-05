"""
Define las estructuras de datos utilizadas por todos los scanners del modulo.
Implementa la estructura del reporte descrita en la Actividad 1.4.

Severidades segun la clasificacion definida en la Actividad 1.1:
CRITICAL, HIGH, MEDIUM, LOW, INFO
"""

from datetime import datetime


# Niveles de severidad definidos en la Actividad 1.1
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

# Peso de cada severidad para el calculo del puntaje
SEVERITY_WEIGHTS = {
    SEVERITY_CRITICAL: 25,
    SEVERITY_HIGH: 15,
    SEVERITY_MEDIUM: 8,
    SEVERITY_LOW: 3,
    SEVERITY_INFO: 0,
}

# Estados de ejecucion de cada scanner
STATUS_COMPLETED = "completed"
STATUS_PARTIAL = "partial"
STATUS_FAILED = "failed"
STATUS_NOT_RUN = "not_run"


def create_finding(
    finding_id,
    title,
    severity,
    owasp_category,
    accessible_description,
    technical_description,
    recommendation,
    evidence=None,
    resources=None,
):
    
    # Crea un diccionario que representa un hallazgo con la estructura descrita en la Actividad 1.4
    if severity not in VALID_SEVERITIES:
        raise ValueError(f"Severidad invalida: {severity}")

    return {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "owasp_category": owasp_category,
        "accessible_description": accessible_description,
        "technical_description": technical_description,
        "recommendation": recommendation,
        "evidence": evidence or {},
        "resources": resources or [],
    }


def create_scanner_result(scanner_name):

    # Crea la estructura base del resultado de un scanner
    return {
        "scanner": scanner_name,
        "status": STATUS_NOT_RUN,
        "score": 0,
        "findings": [],
        "error_message": None,
        "duration_seconds": 0,
    }


def calculate_score(findings):
  
    # Comienza en 100 y resta el peso correspondiente segun severidad para calcular el puntaje
    score = 100
    for finding in findings:
        weight = SEVERITY_WEIGHTS.get(finding.get("severity"), 0)
        score -= weight
    return max(0, score)


def count_by_severity(findings):

    # Retorna un diccionario con el conteo de hallazgos por severidad
    counter = {sev: 0 for sev in VALID_SEVERITIES}
    for finding in findings:
        sev = finding.get("severity")
        if sev in counter:
            counter[sev] += 1
    return counter


def create_base_report(domain):

    # Crea la estructura base del reporte general del modulo
    return {
        "metadata": {
            "domain": domain,
            "start_time": datetime.now().isoformat(),
            "end_time": None,
            "duration_seconds": 0,
            "module_version": "1.0.0",
        },
        "executive_summary": {
            "global_score": 0,
            "total_findings": 0,
            "severity_count": {sev: 0 for sev in VALID_SEVERITIES},
        },
        "scanners": {},
    }
