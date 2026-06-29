import nmap
from tabulate import tabulate
from toolkitTCU.network_module.utils.utils import validate_target
from toolkitTCU.network_module.utils.utils import create_report_folder
from toolkitTCU.network_module.reports.report_exporter import export_udp_report_pdf
from toolkitTCU.network_module.core.scan_results import scan_results
from toolkitTCU.network_module.utils.utils import expand_ip_range

def udp_scanner_menu(target=None):
    create_report_folder()
    scanner = nmap.PortScanner()
    print("\n===================================")
    print("          ESCANEO DE PUERTOS UDP")
    print("===================================")
    if target is None:
        target = input("\nIngrese IP o rango de red: ")
        if not validate_target(target):
            print("\nIP o rango invalido")
            return

    target = expand_ip_range(target)

    print("\nTipo de escaneo:")
    print("1. Escaneo rapido")
    print("2. Escaneo profundo")

    scan_type = input("\nSeleccione opcion: ")

    if scan_type == "1":
        arguments = (
            "-Pn "
            "-n "
            "-T4 "
            "--max-retries 1 "
            "--host-timeout 5m "
            "-sU "
            "--top-ports 100 "
            "-sV "
        )
        ports_label = "Top 100 UDP"

    elif scan_type == "2":
        arguments = (
            "-Pn "
            "-n "
            "-T3 "
            "--max-retries 2 "
            "--host-timeout 15m "
            "-sU "
            "--top-ports 500 "
            "-sV "
        )
        ports_label = "Top 500 UDP"
    else:
        print("\nOpcion invalida")
        return

    print("\n===================================")
    print("CONFIGURACION ESCANEO UDP")
    print("===================================")
    print(f"Objetivo: {target}")
    print(f"Puertos: {ports_label}")
    print("Deteccion servicios y versiones: Activo")

    confirm = input("\n¿Iniciar escaneo? (s/n): ")
    if confirm.lower() != "s":
        print("\nEscaneo cancelado")
        return
    print("\nIniciando escaneo UDP...")
    print("\nEspere, puede tardar unos minutos...")

    try:
        scanner.scan(
            hosts=target,
            arguments=arguments
        )
    except Exception as error:
        print(f"\nError: {error}")
        return

    table_results = []
    export_results = []
    scan_results["udp"] = []

    for host in scanner.all_hosts():
        if "udp" not in scanner[host]:
            continue
        for port in scanner[host]["udp"]:
            port_data = scanner[host]["udp"][port]
            state = port_data.get("state", "N/A")
            service = port_data.get("name", "N/A")
            version = port_data.get("version", "N/A")
            product = port_data.get("product", "")
            full_version = f"{product} {version}"

            table_results.append([
                host,
                port,
                "UDP",
                state,
                service,
                full_version
            ])
            export_results.append({
                "ip": host,
                "port": port,
                "protocol": "UDP",
                "state": state,
                "service": service,
                "version": full_version
            })
            scan_results["udp"].append({
                "ip": host,
                "port": port,
                "protocol": "UDP",
                "state": state,
                "service": service,
                "version": full_version
            })
    if table_results:
        headers = [
            "IP",
            "Puerto",
            "Protocolo",
            "Estado",
            "Servicio",
            "Version"
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
            export_udp_report_pdf(
                export_results,
                target,
                ports_label
            )
    else:
        print("\nNo se encontraron resultados")
