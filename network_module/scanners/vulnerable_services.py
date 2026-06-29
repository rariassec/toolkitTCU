from tabulate import tabulate
from toolkitTCU.network_module.core.scan_results import scan_results
from toolkitTCU.network_module.scanners.vulnerability_checker import search_vulnerabilities
from toolkitTCU.network_module.reports.report_exporter import export_vulnerabilities_report_pdf
from toolkitTCU.network_module.utils.utils import create_report_folder
from toolkitTCU.network_module.core.config import MAX_CVES

def vulnerable_services_menu():
    create_report_folder()

    print("\n===================================")
    print(" DETECTOR SERVICIOS VULNERABLES")
    print("===================================")

    tcp_results = scan_results["tcp"]
    udp_results = scan_results["udp"]

    if not tcp_results and not udp_results:
        print(
            "\nDebe ejecutar primero un escaneo TCP o UDP"
        )
        return

    print("\nSeleccione tipo de analisis:")
    print("1. Vulnerabilidades TCP")
    print("2. Vulnerabilidades UDP")
    print("3. Vulnerabilidades TCP y UDP")

    option = input("\nSeleccione opcion: ")

    if option == "1":
        if not tcp_results:
            print(
                "\nNo existen resultados previos de escaneo TCP"
            )
            return

        all_results = tcp_results
        protocol_selected = "TCP"

    elif option == "2":
        if not udp_results:
            print(
                "\nNo existen resultados previos de escaneo UDP"
            )
            return

        all_results = udp_results
        protocol_selected = "UDP"

    elif option == "3":
        all_results = tcp_results + udp_results
        protocol_selected = "TCP y UDP"
    else:
        print("\nOpcion invalida")
        return

    table_results = []
    export_results = []
    scan_results["vulnerabilities"] = []

    print("\nAnalizando servicios y versiones...")
    print("\nEspere, esto puede tardar unos minutos...")

    for result in all_results:
        service = result["service"]
        version = result["version"]
        protocol = result["protocol"]
        state = result["state"]

        if state not in ["open", "filtered", "open|filtered"]:
            continue
        vulnerabilities = search_vulnerabilities(
            service,
            version
        )
        if not vulnerabilities:
            continue
        vulnerabilities = vulnerabilities[:MAX_CVES]

        for vuln in vulnerabilities:
            table_results.append([
                result["ip"],
                result["port"],
                protocol,
                state,
                service,
                version,
                vuln["cve"],
                vuln["severity"],
                vuln["score"]
            ])

        export_results.append({
            "ip": result["ip"],
            "port": result["port"],
            "protocol": protocol,
            "state": state,
            "service": service,
            "version": version,
            "vulnerabilities": vulnerabilities
        })
        scan_results["vulnerabilities"].append({
            "ip": result["ip"],
            "port": result["port"],
            "protocol": protocol,
            "state": state,
            "service": service,
            "version": version,
            "vulnerabilities": vulnerabilities
        })

    if table_results:
        headers = [
            "IP",
            "Puerto",
            "Protocolo",
            "Estado",
            "Servicio",
            "Version detectada",
            "CVE",
            "Severidad",
            "CVSS"
        ]
        print("\n")

        print(tabulate(
            table_results,
            headers=headers,
            tablefmt="grid"
        ))
        print("\n===================================")
        print("RESUMEN ANALISIS")
        print("===================================")
        print(f"Protocolos analizados: {protocol_selected}")
        print(f"Servicios analizados: {len(export_results)}")
        print(f"Vulnerabilidades encontradas: {len(table_results)}")

        export_option = input(
            "\n¿Exportar PDF con vulnerabilidades? (s/n): "
        )
        if export_option.lower() == "s":
            export_vulnerabilities_report_pdf(
                export_results
            )
    else:
        print(
            "\nNo se encontraron vulnerabilidades asociadas."
        )
