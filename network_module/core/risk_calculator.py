from tabulate import tabulate
from toolkitTCU.network_module.core.scan_results import scan_results
from toolkitTCU.network_module.reports.graphics import (
    generate_risk_gauge,
    generate_severity_chart,
    generate_risk_matrix
)
from toolkitTCU.network_module.core.config import (
    CRITICAL_SERVICES,
    CRITICAL_VULNERABILITY_BONUS,
    HIGH_VULNERABILITY_BONUS,
    EXPOSED_SERVICE_BONUS
)
from toolkitTCU.network_module.reports.report_exporter import (
    export_risk_report_pdf
)

def calculate_impact(vuln):
    impact = 0
    try:
        impact += float(
            vuln["score"]
        )
    except (ValueError, TypeError, KeyError):
        pass
    severity = (
        vuln["severity"]
        .upper()
    )
    if severity == "CRITICAL":
        impact += (
            CRITICAL_VULNERABILITY_BONUS
        )
    elif severity == "HIGH":
        impact += (
            HIGH_VULNERABILITY_BONUS
        )
    service = (
        vuln["service"]
        .lower()
    )
    if service in CRITICAL_SERVICES:
        impact += (
            EXPOSED_SERVICE_BONUS
        )
    return min(
        round(impact,2),
        10
    )

def get_all_vulnerabilities():
    vulnerabilities = []
    for service in scan_results["vulnerabilities"]:
        for vuln in service["vulnerabilities"]:
            vulnerabilities.append({
                "ip": service["ip"],
                "port": service["port"],
                "service": service["service"],
                "version": service["version"],
                "cve": vuln["cve"],
                "severity": vuln["severity"],
                "score": vuln["score"],

                "impact": calculate_impact({

                    "score": vuln["score"],

                    "severity": vuln["severity"],

                    "service": service["service"]

                })
            })
    return vulnerabilities

def dns_risk_score():
    score = 0
    for result in scan_results["dns"]:
        if result["ip_malicious"] == "Si":
            score += 8
        if result["suspicious"] == "Si":
            score += 4
    return score

def suspicious_connections_score():
    score = 0
    for conn in scan_results["suspicious_connections"]:
        if conn["risk"] == "ALTO":
            score += 8
        elif conn["risk"] == "MEDIO":
            score += 5
        elif conn["risk"] == "BAJO":
            score += 2
    return score

def calculate_global_risk():
    vulnerabilities = get_all_vulnerabilities()
    scores = []
    for vuln in vulnerabilities:
        try:
            score = float(vuln["score"])
            scores.append(score)
        except (ValueError, TypeError, KeyError):
            continue
    if scores:
        vuln_score = sum(scores) / len(scores)
    else:
        vuln_score = 0
    dns_score = dns_risk_score()
    conn_score = suspicious_connections_score()
    final_score = (
        vuln_score * 0.7 +
        min(dns_score,10) * 0.15 +
        min(conn_score,10) * 0.15
    )
    return min(
    round(final_score,2),
    10
)

def classify_risk(score):
    if score >= 9:
        return "CRITICO"
    elif score >= 7:
        return "ALTO"
    elif score >= 4:
        return "MEDIO"
    return "BAJO"

def top_vulnerabilities():

    vulnerabilities = (
        get_all_vulnerabilities()
    )
    vulnerabilities.sort(
        key=lambda x: x["impact"],
        reverse=True
    )
    return vulnerabilities[:5]

def build_risk_matrix():
    matrix = {
        "BAJO": 0,
        "MEDIO": 0,
        "ALTO": 0,
        "CRITICO": 0
    }
    vulnerabilities = get_all_vulnerabilities()
    for vuln in vulnerabilities:
        severity = vuln["severity"].upper()
        if severity == "LOW":
            matrix["BAJO"] += 1
        elif severity == "MEDIUM":
            matrix["MEDIO"] += 1
        elif severity == "HIGH":
            matrix["ALTO"] += 1
        elif severity == "CRITICAL":
            matrix["CRITICO"] += 1
    return matrix

def risk_calculator_menu():
    print("\n============================================================")
    print(" CALCULO DE RIESGO DE VULNERABILIDADES")
    print("============================================================")
    vulnerabilities = get_all_vulnerabilities()
    if (
        not scan_results["vulnerabilities"]
        and
        not scan_results["dns"]
        and
        not scan_results["suspicious_connections"]
    ):
        print("\n[!] No hay datos para calcular el riesgo todavia.")
        print("    Ejecute primero alguno de estos analisis y vuelva a esta opcion:")
        print("      - Opcion 1 o 2: escaneo de puertos TCP/UDP")
        print("      - Opcion 4: detector de servicios y versiones vulnerables")
        print("      - Opcion 5: detector de conexiones sospechosas")
        print("      - Opcion 6: analisis DNS")
        return
    risk_score = calculate_global_risk()
    risk_level = classify_risk(
        risk_score
    )
    print(
        f"\nRiesgo general: "
        f"{risk_score}/10"
    )
    print(
        f"Clasificacion: "
        f"{risk_level}"
    )
    scan_results["risk_calculator"] = risk_score
    print("\n===================================")
    print(" TOP 5 VULNERABILIDADES")
    print("===================================")
    top5 = top_vulnerabilities()
    table = []
    for vuln in top5:
        table.append([
            vuln["cve"],
            vuln["severity"],
            vuln["score"],
            vuln["impact"],
            vuln["service"],
            vuln["port"]
        ])

    if top5:
        print(tabulate(
            table,
            headers=[
                "CVE",
                "Severidad",
                "CVSS",
                "Impacto",
                "Servicio",
                "Puerto"
            ],
            tablefmt="grid"
        ))
    else:
        print(
            "\nNo existen vulnerabilidades para priorizar"
        )
    print("\nGenerando graficos...")
    generate_risk_gauge(
        risk_score
    )
    generate_severity_chart(
        vulnerabilities
    )
    generate_risk_matrix(
        build_risk_matrix()
    )
    print(
        "\nGraficos generados correctamente"
    )

    export_option = input(
        "\n¿Exportar PDF con analisis de riesgos? (s/n): "
    )

    if export_option.lower() == "s":
        try:
            export_risk_report_pdf(
                risk_score,
                risk_level,
                vulnerabilities,
                top5
            )
        except Exception as error:
            print(
                f"\nError al generar PDF: {error}"
            )
