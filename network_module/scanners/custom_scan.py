import nmap
from tabulate import tabulate
from toolkitTCU.network_module.utils.utils import validate_target
from toolkitTCU.network_module.utils.utils import create_report_folder
from toolkitTCU.network_module.utils.utils import expand_ip_range
from toolkitTCU.network_module.reports.report_exporter import export_custom_report_pdf
from toolkitTCU.network_module.core.scan_results import scan_results

def ask_flag(question, flag):
    answer = input(question).strip().lower()
    if answer in ("s", "si", "y", "yes"):
        return flag + " "
    return ""

def build_arguments():
    print("\n===================================")
    print("          PARAMETROS PERSONALIZADOS")
    print("===================================")
    print("\nDeje en blanco cualquier opcion que no desee utilizar")

    arguments = ""

    print("\nTecnica de escaneo")
    print("1. tcp connect (sT)")
    print("2. tcp syn (sS, requiere privilegios)")
    print("3. udp (sU)")
    print("4. ninguna (por defecto de nmap)")
    technique = input("\nSeleccione opcion: ").strip()
    if technique == "1":
        arguments += "-sT "
    elif technique == "2":
        arguments += "-sS "
    elif technique == "3":
        arguments += "-sU "

    arguments += ask_flag(
        "\nDetectar servicios y versiones? (s/n): ",
        "-sV"
    )
    arguments += ask_flag(
        "Detectar sistema operativo? (s/n): ",
        "-O"
    )
    arguments += ask_flag(
        "Omitir ping de descubrimiento? (s/n): ",
        "-Pn"
    )
    arguments += ask_flag(
        "Evitar resolucion dns? (s/n): ",
        "-n"
    )

    print("\nPlantilla de velocidad (timing)")
    print("0 a 5, donde 0 es muy lenta y 5 muy rapida. En blanco para omitir")
    timing = input("Seleccione valor: ").strip()
    if timing in ("0", "1", "2", "3", "4", "5"):
        arguments += f"-T{timing} "

    scripts = input("\nScripts nse a ejecutar (ej. vuln,default). En blanco para omitir: ").strip()
    if scripts:
        arguments += f"--script {scripts} "

    extra = input("\nArgumentos adicionales de nmap (en crudo). En blanco para omitir: ").strip()
    if extra:
        arguments += extra + " "

    return arguments.strip()

def custom_scanner_menu(target=None):
    create_report_folder()
    scanner = nmap.PortScanner()
    print("\n===================================")
    print("        ESCANEO PERSONALIZADO")
    print("===================================")

    if target is None:
        target = input("\nIngrese ip o rango de red: ").strip()
        if not validate_target(target):
            print("\nIp o rango invalido")
            return

    target = expand_ip_range(target)

    ports = input("\nIngrese puertos (ej. 1-1024 o 22,80,443). En blanco para 1-1024: ").strip()
    if not ports:
        ports = "1-1024"

    arguments = build_arguments()

    print("\n===================================")
    print("        CONFIGURACION DEL ESCANEO")
    print("===================================")
    print(f"Objetivo: {target}")
    print(f"Puertos: {ports}")
    print(f"Argumentos: {arguments if arguments else 'por defecto'}")

    confirm = input("\nIniciar escaneo? (s/n): ").strip().lower()
    if confirm != "s":
        print("\nEscaneo cancelado")
        return

    print("\nIniciando escaneo personalizado...")
    print("\nEspere, puede tardar unos minutos...")
    try:
        scanner.scan(
            hosts=target,
            ports=ports,
            arguments=arguments
        )
    except Exception as error:
        print(f"\nError: {error}")
        return

    table_results = []
    export_results = []
    scan_results["tcp"] = []
    scan_results["udp"] = []

    for host in scanner.all_hosts():
        for protocol in scanner[host].all_protocols():
            if protocol not in ("tcp", "udp"):
                continue
            for port in scanner[host][protocol]:
                port_data = scanner[host][protocol][port]
                state = port_data.get("state", "N/A")
                service = port_data.get("name", "N/A")
                version = port_data.get("version", "N/A")
                product = port_data.get("product", "")
                full_version = f"{product} {version}"

                table_results.append([
                    host,
                    port,
                    protocol.upper(),
                    state,
                    service,
                    full_version
                ])
                entry = {
                    "ip": host,
                    "port": port,
                    "protocol": protocol.upper(),
                    "state": state,
                    "service": service,
                    "version": full_version
                }
                export_results.append(entry)
                scan_results[protocol].append(entry)

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
            "\nExportar pdf con los resultados? (s/n): "
        ).strip().lower()
        if export_option == "s":
            export_custom_report_pdf(
                export_results,
                target,
                ports
            )
    else:
        print("\nNo se encontraron resultados")
