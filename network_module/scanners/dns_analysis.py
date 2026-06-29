from datetime import datetime
import requests
from tabulate import tabulate
import toolkitTCU.network_module.core.config as _config
from toolkitTCU.network_module.core.config import (
    VT_IP_URL,
    HTTP_TIMEOUT
)
from toolkitTCU.network_module.utils.utils import (
    create_report_folder,
    resolve_domain,
    reverse_dns_lookup,
    is_valid_ip,
    is_valid_domain,
    is_private_ip
)
from toolkitTCU.network_module.core.scan_results import scan_results
from toolkitTCU.network_module.reports.report_exporter import (export_dns_report_pdf)

ip_cache = {}

SUSPICIOUS_TLDS = [
    ".xyz",
    ".top",
    ".click",
    ".gq",
    ".tk",
    ".ml",
    ".cf"
]

def get_ip_reputation(ip):
    if ip in ip_cache:
        return ip_cache[ip]
    vt_api_key = _config.VT_API_KEY
    if not vt_api_key:
        ip_cache[ip] = "Sin API Key"
        return "Sin API Key"
    headers = {"x-apikey": vt_api_key}
    try:
        response = requests.get(
            VT_IP_URL + ip,
            headers=headers,
            timeout=HTTP_TIMEOUT
        )
        if response.status_code == 429:
            ip_cache[ip] = "Rate Limit"
            return "Rate Limit"
        if response.status_code != 200:
            ip_cache[ip] = "Desconocido"
            return "Desconocido"
        data = response.json()
        malicious_count = (
            data["data"]["attributes"]
            .get(
                "last_analysis_stats",
                {}
            )
            .get(
                "malicious",
                0
            )
        )

        if malicious_count > 0:
            result = "Si"
        else:
            result = "No"
        ip_cache[ip] = result
        return result

    except Exception:
        ip_cache[ip] = "Error"
        return "Error"

def analyze_domain(domain):
    score = 0
    reasons = []
    domain = domain.lower()

    if any(
        domain.endswith(tld)
        for tld in SUSPICIOUS_TLDS
    ):
        score += 1
        reasons.append("TLD sospechoso")
    if len(domain) > 30:
        score += 1
        reasons.append(
            "Dominio largo"
        )
    digit_count = sum(
        c.isdigit()
        for c in domain
    )
    if digit_count >= 5:
        score += 1
        reasons.append(
            "Muchos numeros"
        )
    if score >= 1:
        return (
            "Si",
            ", ".join(reasons)
        )
    return (
        "No",
        "-"
    )

def dns_analysis_menu(target=None):
    create_report_folder()
    print("\n===================================")
    print("           ANALISIS DNS")
    print("===================================")

    if target:
        value = str(target).strip().lower()
        print(f"\nObjetivo: {value}")
    else:
        value = input(
            "\nIngrese dominio o IP: "
        ).strip().lower()

    if not value:
        print(
            "\nDebe ingresar un dominio o una IP"
        )
        return

    value = (
        value
        .replace("https://", "")
        .replace("http://", "")
        .split("/")[0]
    )

    is_ip = is_valid_ip(value)
    is_domain = is_valid_domain(value)

    if not is_ip and not is_domain:
        print("\nFormato de IP o dominio incorrecto")
        return

    print("\nTipo resolucion:")
    print("1. Directa (Dominio -> IP)")
    print("2. Inversa (IP -> Dominio)")

    option = input(
        "\nSeleccione opcion: "
    )

    if option == "1" and is_ip:
        print("\nIngreso una IP. Debe seleccionar Resolucion Inversa")
        return

    if option == "2" and is_domain:
        print("\nIngreso un dominio. Debe seleccionar Resolucion Directa")
        return

    scan_results["dns"] = []
    results = []

    if option == "1":

        suspicious, _ = (
            analyze_domain(value)
        )

        resolved_ip = resolve_domain(
            value
        )

        if not resolved_ip:

            result = {
                "timestamp": datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "type": "Directa",
                "value": value,
                "resolved": "No resuelto",
                "ip_malicious": "-",
                "suspicious": suspicious
            }

            results.append(result)

        else:

            if is_private_ip(resolved_ip):
                ip_malicious = "Red Privada"
            else:
                ip_malicious = get_ip_reputation(
                    resolved_ip
                )

            result = {
                "timestamp": datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "type": "Directa",
                "value": value,
                "resolved": resolved_ip,
                "ip_malicious": ip_malicious,
                "suspicious": suspicious
            }

            results.append(result)

    elif option == "2":
        domain = reverse_dns_lookup(
            value
        )
        if not domain:
            domain = ("Sin registro")

        if is_private_ip(value):
            ip_malicious = "Red Privada"
        else:
            ip_malicious = get_ip_reputation(
                value
            )
        result = {
            "timestamp": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "type": "Inversa",
            "value": value,
            "resolved": domain,
            "ip_malicious": ip_malicious,
            "suspicious": "No"
        }
        results.append(result)
    else:
        print("\nOpcion incorrecta")
        return

    scan_results["dns"] = results
    table_results = []

    for result in results:

        table_results.append([
            result["type"],
            result["value"],
            result["resolved"],
            result["ip_malicious"],
            result["suspicious"]
        ])

    print("\n")

    print(tabulate(
        table_results,
        headers=[
            "Tipo",
            "Valor",
            "Resultado",
            "IP Maliciosa",
            "Dominio Sospechoso"
        ],
        tablefmt="grid"
    ))
    export_option = input(
        "\n¿Exportar PDF? (s/n): "
    )
    if export_option.lower() == "s":
        export_dns_report_pdf(results)
