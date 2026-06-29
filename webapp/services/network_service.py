
import nmap

from toolkitTCU.network_module.core.scan_results import scan_results
from toolkitTCU.network_module.core import config as net_config
from toolkitTCU.network_module.utils.utils import (
    validate_target,
    is_valid_domain,
    is_valid_ip,
    is_private_ip,
    resolve_domain,
    reverse_dns_lookup,
    expand_ip_range,
    create_report_folder,
)
from toolkitTCU.network_module.scanners.vulnerability_checker import search_vulnerabilities
from toolkitTCU.network_module.scanners import dns_analysis as dns_mod
from toolkitTCU.network_module.scanners import suspicious_connections as susp_mod
from toolkitTCU.network_module.core.risk_calculator import (
    get_all_vulnerabilities,
    calculate_global_risk,
    classify_risk,
    top_vulnerabilities,
    build_risk_matrix,
)
from toolkitTCU.network_module.utils import vt_key_manager
from toolkitTCU.network_module.utils import api_key_manager

def resolve_objective(raw):
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Debe indicar una IP, dominio o rango.")

    if validate_target(raw):
        return raw, raw, None

    if is_valid_domain(raw):
        ip = resolve_domain(raw)
        if ip:
            return ip, raw, f"Dominio {raw} resuelto a {ip}"
        raise ValueError(f"No se pudo resolver el dominio {raw}.")

    raise ValueError(
        "Objetivo invalido. Use una IP, un dominio o un rango "
        "(ej. 192.168.1.1-192.168.1.10)."
    )

def _parse_ports(scanner, host, proto):
    rows = []
    if proto not in scanner[host]:
        return rows
    for port in scanner[host][proto]:
        data = scanner[host][proto][port]
        product = data.get("product", "")
        version = data.get("version", "")
        rows.append({
            "ip": host,
            "port": port,
            "protocol": proto.upper(),
            "state": data.get("state", "N/A"),
            "service": data.get("name", "N/A"),
            "version": f"{product} {version}".strip(),
        })
    return rows

def tcp_scan(target, depth="quick"):
    create_report_folder()
    target = expand_ip_range(target)
    ports = "1-1024" if depth == "quick" else "1-65535"
    arguments = "-Pn -n -T4 --min-rate 1000 --max-retries 1 -sT -sV"

    scanner = nmap.PortScanner()
    scanner.scan(hosts=target, ports=ports, arguments=arguments)

    results = []
    for host in scanner.all_hosts():
        results.extend(_parse_ports(scanner, host, "tcp"))

    scan_results["tcp"] = results
    return {
        "target": target,
        "ports": ports,
        "depth": depth,
        "count": len(results),
        "rows": results,
    }

def udp_scan(target, depth="quick"):
    create_report_folder()
    target = expand_ip_range(target)
    if depth == "quick":
        arguments = ("-Pn -n -T4 --max-retries 1 --host-timeout 5m "
                     "-sU --top-ports 100 -sV")
        ports_label = "Top 100 UDP"
    else:
        arguments = ("-Pn -n -T3 --max-retries 2 --host-timeout 15m "
                     "-sU --top-ports 500 -sV")
        ports_label = "Top 500 UDP"

    scanner = nmap.PortScanner()
    scanner.scan(hosts=target, arguments=arguments)

    results = []
    for host in scanner.all_hosts():
        results.extend(_parse_ports(scanner, host, "udp"))

    scan_results["udp"] = results
    return {
        "target": target,
        "ports": ports_label,
        "depth": depth,
        "count": len(results),
        "rows": results,
    }

def custom_scan(target, ports="1-1024", options=None):
    create_report_folder()
    options = options or {}
    target = expand_ip_range(target)
    ports = ports.strip() or "1-1024"

    arguments = ""
    technique = options.get("technique", "none")
    arguments += {"connect": "-sT ", "syn": "-sS ", "udp": "-sU "}.get(technique, "")
    if options.get("service_detection"):
        arguments += "-sV "
    if options.get("os_detection"):
        arguments += "-O "
    if options.get("skip_ping"):
        arguments += "-Pn "
    if options.get("no_dns"):
        arguments += "-n "
    timing = str(options.get("timing", "")).strip()
    if timing in ("0", "1", "2", "3", "4", "5"):
        arguments += f"-T{timing} "
    scripts = (options.get("scripts") or "").strip()
    if scripts:
        arguments += f"--script {scripts} "
    extra = (options.get("extra") or "").strip()
    if extra:
        arguments += extra + " "
    arguments = arguments.strip()

    scanner = nmap.PortScanner()
    scanner.scan(hosts=target, ports=ports, arguments=arguments)

    results = []
    scan_results["tcp"] = []
    scan_results["udp"] = []
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            if proto not in ("tcp", "udp"):
                continue
            rows = _parse_ports(scanner, host, proto)
            results.extend(rows)
            scan_results[proto].extend(rows)

    return {
        "target": target,
        "ports": ports,
        "arguments": arguments or "por defecto",
        "count": len(results),
        "rows": results,
    }

def vulnerability_scan(protocol="both"):
    tcp_results = scan_results.get("tcp", [])
    udp_results = scan_results.get("udp", [])
    if not tcp_results and not udp_results:
        raise ValueError("Debe ejecutar primero un escaneo TCP o UDP.")

    if protocol == "tcp":
        sources = tcp_results
    elif protocol == "udp":
        sources = udp_results
    else:
        sources = tcp_results + udp_results

    found = []
    scan_results["vulnerabilities"] = []
    for result in sources:
        if result.get("state") not in ("open", "filtered", "open|filtered"):
            continue
        vulns = search_vulnerabilities(result["service"], result["version"])
        if not vulns:
            continue
        vulns = vulns[:net_config.MAX_CVES]
        entry = {
            "ip": result["ip"],
            "port": result["port"],
            "protocol": result["protocol"],
            "state": result["state"],
            "service": result["service"],
            "version": result["version"],
            "vulnerabilities": vulns,
        }
        scan_results["vulnerabilities"].append(entry)
        for vuln in vulns:
            found.append({
                "ip": result["ip"],
                "port": result["port"],
                "protocol": result["protocol"],
                "service": result["service"],
                "version": result["version"],
                "cve": vuln.get("cve"),
                "severity": vuln.get("severity"),
                "score": vuln.get("score"),
            })

    return {
        "protocol": protocol,
        "services_analyzed": len(scan_results["vulnerabilities"]),
        "count": len(found),
        "rows": found,
    }

def dns_analysis(value, mode="auto"):
    value = (value or "").strip().lower()
    if not value:
        raise ValueError("Debe indicar un dominio o una IP.")
    value = value.replace("https://", "").replace("http://", "").split("/")[0]

    is_ip = is_valid_ip(value)
    is_domain = is_valid_domain(value)
    if not is_ip and not is_domain:
        raise ValueError("Formato de IP o dominio incorrecto.")

    if mode == "auto":
        mode = "direct" if is_domain else "reverse"
    if mode == "direct" and is_ip:
        raise ValueError("Ingreso una IP: use resolucion inversa.")
    if mode == "reverse" and is_domain:
        raise ValueError("Ingreso un dominio: use resolucion directa.")

    from datetime import datetime
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    scan_results["dns"] = []

    if mode == "direct":
        suspicious, reasons = dns_mod.analyze_domain(value)
        resolved_ip = resolve_domain(value)
        if not resolved_ip:
            result = {"timestamp": ts, "type": "Directa", "value": value,
                      "resolved": "No resuelto", "ip_malicious": "-",
                      "suspicious": suspicious, "reasons": reasons}
        else:
            if is_private_ip(resolved_ip):
                ip_malicious = "Red Privada"
            else:
                ip_malicious = dns_mod.get_ip_reputation(resolved_ip)
            result = {"timestamp": ts, "type": "Directa", "value": value,
                      "resolved": resolved_ip, "ip_malicious": ip_malicious,
                      "suspicious": suspicious, "reasons": reasons}
    else:
        domain = reverse_dns_lookup(value) or "Sin registro"
        if is_private_ip(value):
            ip_malicious = "Red Privada"
        else:
            ip_malicious = dns_mod.get_ip_reputation(value)
        result = {"timestamp": ts, "type": "Inversa", "value": value,
                  "resolved": domain, "ip_malicious": ip_malicious,
                  "suspicious": "No", "reasons": "-"}

    scan_results["dns"] = [result]
    return {"rows": [result]}

def suspicious_connections(duration_seconds=60, analysis_type="BASICO"):
    from scapy.all import sniff, IP, TCP, UDP
    from collections import defaultdict

    analysis_type = "AVANZADO" if str(analysis_type).upper() == "AVANZADO" else "BASICO"
    connections = []
    packet_counter = defaultdict(int)
    destination_counter = defaultdict(set)
    detected = set()
    scan_results["suspicious_connections"] = []

    def process_packet(packet):
        if IP not in packet:
            return
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        if not (susp_mod.is_private_ip(src_ip) and not susp_mod.is_private_ip(dst_ip)):
            return

        protocol, port = "OTRO", "N/A"
        if TCP in packet:
            protocol, port = "TCP", packet[TCP].dport
        elif UDP in packet:
            protocol, port = "UDP", packet[UDP].dport
        if port in net_config.DNS_PORTS:
            return

        key = (src_ip, dst_ip, port, protocol)
        packet_counter[src_ip] += 1
        if key in detected:
            return
        detected.add(key)
        destination_counter[src_ip].add(dst_ip)

        if analysis_type == "BASICO":
            country, malicious = "No Analizado", "No"
        else:
            country, malicious = susp_mod.get_ip_reputation(dst_ip)

        suspicious, risk_score, anomalous = "No", 0, "No"
        if analysis_type == "AVANZADO" and country in net_config.HIGH_RISK_COUNTRIES:
            suspicious, risk_score = "Si", risk_score + 2
        if port in net_config.SUSPICIOUS_PORTS:
            suspicious, risk_score = "Si", risk_score + 1
        if (analysis_type == "AVANZADO"
                and packet_counter[src_ip] > net_config.ANOMALOUS_PACKET_THRESHOLD):
            suspicious, anomalous, risk_score = "Si", "Si", risk_score + 2
        if (analysis_type == "AVANZADO"
                and len(destination_counter[src_ip]) > net_config.DESTINATION_THRESHOLD):
            suspicious, risk_score = "Si", risk_score + 2
        if malicious == "Si":
            suspicious, risk_score = "Si", risk_score + 3

        risk = "ALTO" if risk_score >= 4 else "MEDIO" if risk_score >= 2 else "BAJO"
        result = {
            "src_ip": src_ip, "dst_ip": dst_ip, "port": port, "protocol": protocol,
            "country": country, "malicious": malicious, "risk": risk,
            "suspicious": suspicious, "anomalous_traffic": anomalous,
            "packet_count": packet_counter[src_ip],
            "unique_destinations": len(destination_counter[src_ip]),
        }
        connections.append(result)
        scan_results["suspicious_connections"].append(result)

    sniff(filter="tcp or udp", prn=process_packet, timeout=duration_seconds, store=False)

    return {
        "analysis_type": analysis_type,
        "duration_seconds": duration_seconds,
        "total": len(connections),
        "suspicious": sum(1 for c in connections if c["suspicious"] == "Si"),
        "high_risk": sum(1 for c in connections if c["risk"] == "ALTO"),
        "medium_risk": sum(1 for c in connections if c["risk"] == "MEDIO"),
        "rows": connections,
    }

def risk_summary():
    has_data = any(scan_results.get(k) for k in
                   ("vulnerabilities", "dns", "suspicious_connections"))
    if not has_data:
        raise ValueError(
            "No hay datos para calcular el riesgo. Ejecute primero un escaneo "
            "de puertos y la deteccion de vulnerabilidades, DNS o conexiones."
        )
    score = calculate_global_risk()
    scan_results["risk_calculator"] = score
    return {
        "score": score,
        "level": classify_risk(score),
        "matrix": build_risk_matrix(),
        "top": top_vulnerabilities(),
        "total_vulnerabilities": len(get_all_vulnerabilities()),
    }

def save_report():
    import os
    from toolkitTCU.common.reports import save_module_report
    from toolkitTCU.integration import network_facade

    has_data = any(scan_results.get(k) for k in
                   ("tcp", "udp", "vulnerabilities", "dns", "suspicious_connections"))
    if not has_data:
        raise ValueError("No hay datos de red para reportar. Ejecute algun escaneo primero.")

    result = network_facade.build_module_result()
    json_path, pdf_path = save_module_report(
        result, "reporte_red", "Reporte de Analisis de Red")
    return {
        "ok": True,
        "json": os.path.basename(json_path),
        "pdf": os.path.basename(pdf_path),
        "message": "Reporte de red generado (JSON + PDF).",
    }

def state_summary():
    return {
        "tcp": len(scan_results.get("tcp", [])),
        "udp": len(scan_results.get("udp", [])),
        "vulnerabilities": len(get_all_vulnerabilities()),
        "dns": len(scan_results.get("dns", [])),
        "suspicious_connections": len(scan_results.get("suspicious_connections", [])),
        "risk": scan_results.get("risk_calculator", 0),
    }

def _mask(key):
    if not key:
        return ""
    return key[:8] + "*" * max(0, len(key) - 8)

def get_api_keys():
    return {
        "virustotal": {"configured": bool(net_config.VT_API_KEY),
                       "masked": _mask(net_config.VT_API_KEY)},
        "nvd": {"configured": bool(net_config.NVD_API_KEY),
                "masked": _mask(net_config.NVD_API_KEY)},
    }

def set_api_key(provider, key):
    key = (key or "").strip()
    if provider == "virustotal":
        if key:
            vt_key_manager.save_vt_key(key)
        else:
            raise ValueError("La clave no puede estar vacia.")
    elif provider == "nvd":
        if key:
            api_key_manager.save_nvd_key(key)
        else:
            raise ValueError("La clave no puede estar vacia.")
    else:
        raise ValueError("Proveedor desconocido.")
    return get_api_keys()

def delete_api_key(provider):
    import os
    if provider == "virustotal":
        if os.path.isfile(vt_key_manager.CREDENTIALS_FILE):
            os.remove(vt_key_manager.CREDENTIALS_FILE)
        os.environ.pop("VT_API_KEY", None)
        net_config.VT_API_KEY = ""
    elif provider == "nvd":
        api_key_manager.delete_nvd_key()
    else:
        raise ValueError("Proveedor desconocido.")
    return get_api_keys()
