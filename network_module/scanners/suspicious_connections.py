from scapy.all import sniff, IP, TCP, UDP
import requests
import ipaddress
from collections import defaultdict
from tabulate import tabulate
import time

import toolkitTCU.network_module.core.config as _config
from toolkitTCU.network_module.core.config import (
    VT_IP_URL,
    DETECTION_DURATION_OPTIONS,
    SENSITIVITY_LEVELS,
    ANOMALOUS_PACKET_THRESHOLD,
    SUSPICIOUS_PORTS,
    HIGH_RISK_COUNTRIES,
    DESTINATION_THRESHOLD,
    DNS_PORTS,
    HTTP_TIMEOUT
)
from toolkitTCU.network_module.utils.utils import (
    create_report_folder
)
from toolkitTCU.network_module.reports.report_exporter import (
    export_suspicious_report_pdf
)
from toolkitTCU.network_module.core.scan_results import scan_results

ip_cache = {}

def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def get_ip_reputation(ip):
    if ip in ip_cache:
        return ip_cache[ip]
    if is_private_ip(ip):
        result = (
            "Red Privada",
            "No"
        )
        ip_cache[ip] = result
        return result
    vt_api_key = _config.VT_API_KEY
    if not vt_api_key:
        result = ("Sin API Key", "No")
        ip_cache[ip] = result
        return result
    headers = {
        "x-apikey": vt_api_key
    }
    try:
        response = requests.get(
            VT_IP_URL + ip,
            headers=headers,
            timeout=HTTP_TIMEOUT
        )
        if response.status_code == 429:
            result = (
                "Rate Limit",
                "No"
            )

            ip_cache[ip] = result
            return result

        if response.status_code != 200:
            result = (
                "Desconocido",
                "No"
            )
            ip_cache[ip] = result
            return result

        data = response.json()
        attributes = data["data"]["attributes"]
        country = attributes.get(
            "country",
            "Desconocido"
        )
        malicious_count = attributes.get(
            "last_analysis_stats",
            {}
        ).get(
            "malicious",
            0
        )

        if malicious_count > 0:
            malicious_status = "Si"
        else:
            malicious_status = "No"
        result = (
            country,
            malicious_status
        )
        ip_cache[ip] = result

        return result
    except Exception:

        result = (
            "Error",
            "No"
        )
        ip_cache[ip] = result
        return result

def suspicious_detector_menu():
    create_report_folder()

    print("\n===================================")
    print(" DETECTOR CONEXIONES SOSPECHOSAS")
    print("===================================")

    print("\nDuracion monitoreo:")
    print("1. 1 minuto")
    print("2. 5 minutos")
    print("3. Continuo")

    duration_option = input(
        "\nSeleccione opcion: "
    )
    if duration_option not in DETECTION_DURATION_OPTIONS:
        print("\nOpcion invalida")
        return
    duration = DETECTION_DURATION_OPTIONS[
        duration_option
    ]
    print("\nTipo analisis:")
    print("1. Basico")
    print("2. Avanzado")

    analysis_option = input(
        "\nSeleccione opcion: "
    )

    if analysis_option not in SENSITIVITY_LEVELS:
        print("\nOpcion invalida")
        return

    analysis_type = SENSITIVITY_LEVELS[
        analysis_option
    ]
    print("\n===================================")
    print(" MONITOREO ACTIVADO")
    print("===================================")

    print("\nCapturando trafico de red...")

    connections = []
    packet_counter = defaultdict(int)
    destination_counter = defaultdict(set)

    detected_connections = set()
    scan_results["suspicious_connections"] = []

    def process_packet(packet):
        if IP not in packet:
            return
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if not (
            is_private_ip(src_ip)
            and
            not is_private_ip(dst_ip)
        ):
            return

        protocol = "OTRO"
        port = "N/A"

        if TCP in packet:
            protocol = "TCP"
            port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            port = packet[UDP].dport

        if port in DNS_PORTS:
            return

        connection_key = (
            src_ip,
            dst_ip,
            port,
            protocol
        )

        packet_counter[src_ip] += 1
        if connection_key in detected_connections:
            return
        detected_connections.add(
            connection_key
        )

        destination_counter[src_ip].add(dst_ip)

        if analysis_type == "BASICO":
            country = "No Analizado"
            malicious = "No"
        else:
            country, malicious = get_ip_reputation(
                dst_ip
            )

        suspicious = "No"
        risk = "BAJO"
        anomalous_traffic = "No"
        risk_score = 0

        if (
            analysis_type == "AVANZADO"
            and
            country in HIGH_RISK_COUNTRIES
        ):
            suspicious = "Si"
            risk_score += 2

        if port in SUSPICIOUS_PORTS:
            suspicious = "Si"
            risk_score += 1

        if (
            analysis_type == "AVANZADO"
            and
            packet_counter[src_ip]
            >
            ANOMALOUS_PACKET_THRESHOLD
        ):
            suspicious = "Si"
            anomalous_traffic = "Si"
            risk_score += 2

        if (
            analysis_type == "AVANZADO"
            and
            len(destination_counter[src_ip])
            >
            DESTINATION_THRESHOLD
        ):
            suspicious = "Si"
            risk_score += 2

        if malicious == "Si":
            suspicious = "Si"
            risk_score += 3

        if risk_score >= 4:
            risk = "ALTO"

        elif risk_score >= 2:
            risk = "MEDIO"

        else:
            risk = "BAJO"

        result = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "port": port,
            "protocol": protocol,
            "country": country,
            "malicious": malicious,
            "risk": risk,
            "suspicious": suspicious,
            "anomalous_traffic": anomalous_traffic,
            "packet_count": packet_counter[src_ip],
            "unique_destinations": len(destination_counter[src_ip]),
        }

        connections.append(result)
        scan_results[
            "suspicious_connections"
        ].append(result)

    start_time = time.time()
    try:
        if duration == -1:
            sniff(
                filter="tcp or udp",
                prn=process_packet,
                store=False
            )
        else:
            sniff(
                filter="tcp or udp",
                prn=process_packet,
                timeout=duration,
                store=False
            )
    except KeyboardInterrupt:

        print("\nMonitoreo detenido")
    print("\n===================================")
    print(" DETECTOR PAUSADO")
    print("===================================")

    end_time = time.time()
    elapsed_seconds = int(end_time - start_time)
    hours = elapsed_seconds // 3600
    minutes = (elapsed_seconds % 3600) // 60
    seconds = elapsed_seconds % 60

    if hours > 0:
        monitoring_time = (
            f"{hours} h "
            f"{minutes} min "
            f"{seconds} seg"
        )
    elif minutes > 0:
        monitoring_time = (
            f"{minutes} min "
            f"{seconds} seg"
        )
    else:
        monitoring_time = (
            f"{seconds} seg"
        )
    total_connections = len(connections)
    suspicious_count = sum(
        1
        for c in connections
        if c["suspicious"] == "Si"
    )
    high_risk_count = sum(
        1
        for c in connections
        if c["risk"] == "ALTO"
    )
    print("\n===================================")
    print(" RESUMEN DEL MONITOREO")
    print("===================================")

    print(
        f"\nTotal conexiones analizadas: "
        f"{total_connections}"
    )
    print(
        f"Conexiones sospechosas: "
        f"{suspicious_count}"
    )
    print(
        f"Conexiones de alto riesgo: "
        f"{high_risk_count}"
    )

    medium_risk_count = sum(
        1
        for c in connections
        if c["risk"] == "MEDIO"
    )

    print(
        f"Conexiones de riesgo medio: "
        f"{medium_risk_count}"
    )

    countries_detected = set(
        c["country"]
        for c in connections
        if c["country"] != "No Analizado"
    )

    if countries_detected:
        print(
            f"Paises detectados: "
            f"{', '.join(sorted(countries_detected))}"
        )

    if connections:
        table_results = []
        for conn in connections:
            if analysis_type == "BASICO":
                table_results.append([
                    conn["src_ip"],
                    conn["dst_ip"],
                    conn["port"],
                    conn["protocol"],
                    conn["suspicious"]
                ])
            else:
                table_results.append([
                    conn["src_ip"],
                    conn["dst_ip"],
                    conn["port"],
                    conn["protocol"],
                    conn["country"],
                    conn["malicious"],
                    conn["anomalous_traffic"],
                    conn["packet_count"],
                    conn["unique_destinations"],
                    conn["risk"],
                    conn["suspicious"]
                ])
        if analysis_type == "BASICO":
            headers = [
                "IP Origen",
                "IP Destino",
                "Puerto",
                "Protocolo",
                "Sospechosa"
            ]
        else:
            headers = [
                "IP Origen",
                "IP Destino",
                "Puerto",
                "Protocolo",
                "Pais",
                "Maliciosa",
                "Trafico anomalo",
                "Paquetes",
                "Destinos",
                "Riesgo",
                "Sospechosa"
            ]
        print("\n")

        print(tabulate(
            table_results,
            headers=headers,
            tablefmt="grid"
        ))
        export_option = input(
            "\n¿Exportar PDF con los resultados? (s/n): "
        )
        if export_option.lower() == "s":
            export_suspicious_report_pdf(
                connections,
                monitoring_time,
                analysis_type
            )
    else:
        print(
            "\nNo se detectaron conexiones sospechosas."
        )
