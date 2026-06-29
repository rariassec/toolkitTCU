
from toolkitTCU.common import findings as F
from toolkitTCU.network_module.core.scan_results import scan_results
from toolkitTCU.network_module.core.risk_calculator import (
    get_all_vulnerabilities,
    calculate_global_risk,
    classify_risk,
)
from toolkitTCU.network_module.core.config import CRITICAL_SERVICES

def _findings_from_vulnerabilities():
    out = []
    for vuln in get_all_vulnerabilities():
        cve = vuln.get("cve", "N/A")
        severity = F.normalize_severity(vuln.get("severity"))
        if severity == F.SEVERITY_INFO and vuln.get("score"):
            severity = F.severity_from_cvss(vuln.get("score"))
        out.append(F.create_finding(
            module=F.MODULE_NETWORK,
            finding_id=f"NET-VULN-{cve}",
            title=f"{cve} en {vuln.get('service', 'servicio')} "
                  f"({vuln.get('ip')}:{vuln.get('port')})",
            severity=severity,
            category="Vulnerabilidad de servicio",
            description=(
                f"El servicio {vuln.get('service')} {vuln.get('version', '')} "
                f"expuesto en {vuln.get('ip')}:{vuln.get('port')} es afectado "
                f"por la vulnerabilidad {cve} (CVSS {vuln.get('score')})."
            ),
            recommendation=(
                "Actualice o parchee el servicio afectado a una version sin la "
                "vulnerabilidad, o restrinja el acceso al puerto."
            ),
            evidence={
                "ip": vuln.get("ip"),
                "port": vuln.get("port"),
                "service": vuln.get("service"),
                "version": vuln.get("version"),
                "cvss": vuln.get("score"),
                "impacto": vuln.get("impact"),
            },
        ))
    return out

def _findings_from_suspicious_connections():
    out = []
    for i, conn in enumerate(scan_results.get("suspicious_connections", []), 1):
        risk = conn.get("risk", "")
        if not risk:
            continue
        out.append(F.create_finding(
            module=F.MODULE_NETWORK,
            finding_id=f"NET-CONN-{i}",
            title=f"Conexion saliente sospechosa a {conn.get('dst_ip')}:{conn.get('port')}",
            severity=risk,
            category="Conexion sospechosa",
            description=(
                f"Conexion {conn.get('protocol')} desde {conn.get('src_ip')} "
                f"hacia {conn.get('dst_ip')}:{conn.get('port')} "
                f"(pais: {conn.get('country')}, maliciosa: {conn.get('malicious')})."
            ),
            recommendation=(
                "Verifique el proceso que origina la conexion y bloquee el "
                "destino si no corresponde a trafico legitimo."
            ),
            evidence={
                "destino": f"{conn.get('dst_ip')}:{conn.get('port')}",
                "pais": conn.get("country"),
                "maliciosa": conn.get("malicious"),
                "trafico_anomalo": conn.get("anomalous_traffic"),
                "paquetes": conn.get("packet_count"),
                "destinos_unicos": conn.get("unique_destinations"),
            },
        ))
    return out

def _findings_from_dns():
    out = []
    for i, entry in enumerate(scan_results.get("dns", []), 1):
        malicious = entry.get("ip_malicious") == "Si"
        suspicious = entry.get("suspicious") == "Si"
        if not (malicious or suspicious):
            continue
        severity = F.SEVERITY_HIGH if malicious else F.SEVERITY_MEDIUM
        out.append(F.create_finding(
            module=F.MODULE_NETWORK,
            finding_id=f"NET-DNS-{i}",
            title=f"Resolucion DNS de riesgo: {entry.get('value')}",
            severity=severity,
            category="Analisis DNS",
            description=(
                f"La consulta {entry.get('type')} de '{entry.get('value')}' "
                f"resolvio a '{entry.get('resolved')}'. "
                f"IP maliciosa: {entry.get('ip_malicious')}, "
                f"dominio sospechoso: {entry.get('suspicious')}."
            ),
            recommendation=(
                "Evite comunicarse con el dominio/IP y revise por que un equipo "
                "intenta resolver este nombre."
            ),
            evidence={
                "consulta": entry.get("value"),
                "resuelto": entry.get("resolved"),
                "ip_maliciosa": entry.get("ip_malicious"),
            },
        ))
    return out

def _findings_from_exposed_services():
    out = []
    seen = set()
    for entry in scan_results.get("tcp", []) + scan_results.get("udp", []):
        if str(entry.get("state", "")).lower() != "open":
            continue
        service = str(entry.get("service", "")).lower()
        if service not in CRITICAL_SERVICES:
            continue
        key = (entry.get("ip"), entry.get("port"), service)
        if key in seen:
            continue
        seen.add(key)
        out.append(F.create_finding(
            module=F.MODULE_NETWORK,
            finding_id=f"NET-SVC-{entry.get('ip')}-{entry.get('port')}",
            title=f"Servicio critico expuesto: {service} en {entry.get('ip')}:{entry.get('port')}",
            severity=F.SEVERITY_MEDIUM,
            category="Servicio expuesto",
            description=(
                f"El servicio critico '{service}' ({entry.get('version')}) esta "
                f"abierto en {entry.get('ip')}:{entry.get('port')} ({entry.get('protocol')})."
            ),
            recommendation=(
                "Confirme que la exposicion del servicio es necesaria y "
                "restrinja el acceso mediante firewall si corresponde."
            ),
            evidence={
                "ip": entry.get("ip"),
                "port": entry.get("port"),
                "protocol": entry.get("protocol"),
                "service": service,
                "version": entry.get("version"),
            },
        ))
    return out

def collect_findings():
    findings = []
    findings.extend(_findings_from_vulnerabilities())
    findings.extend(_findings_from_suspicious_connections())
    findings.extend(_findings_from_dns())
    findings.extend(_findings_from_exposed_services())
    return findings

def build_module_result():
    result = F.create_module_result(F.MODULE_NETWORK)
    result["findings"] = collect_findings()

    has_data = any(scan_results.get(k) for k in
                   ("vulnerabilities", "dns", "suspicious_connections", "tcp", "udp"))
    if has_data:
        global_risk = calculate_global_risk()
        result["summary"] = {
            "riesgo_global_0_10": global_risk,
            "clasificacion": classify_risk(global_risk),
            "puertos_tcp": len(scan_results.get("tcp", [])),
            "puertos_udp": len(scan_results.get("udp", [])),
        }
    else:
        result["status"] = "not_run"
    return result

def run_interactive():
    from toolkitTCU.network_module.main import main as network_main
    network_main()
    return build_module_result()
