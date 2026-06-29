from toolkitTCU.network_module.scanners.tcp_scanner import tcp_scanner_menu
from toolkitTCU.network_module.scanners.udp_scanner import udp_scanner_menu
from toolkitTCU.network_module.scanners.custom_scan import custom_scanner_menu
from toolkitTCU.network_module.scanners.vulnerable_services import vulnerable_services_menu
from toolkitTCU.network_module.scanners.suspicious_connections import suspicious_detector_menu
from toolkitTCU.network_module.scanners.dns_analysis import dns_analysis_menu
from toolkitTCU.network_module.core.risk_calculator import risk_calculator_menu
from toolkitTCU.network_module.reports.reporting import reporting_menu
from toolkitTCU.network_module.utils.utils import validate_target, is_valid_domain, resolve_domain
from toolkitTCU.network_module.utils.api_key_manager import configure_api_keys_menu

def pedir_objetivo():
    print("\n============================================================")
    print(" ANALISIS DE RED")
    print("============================================================")
    print(" Analiza una IP, dominio o rango de red en busca de puertos")
    print(" abiertos, servicios vulnerables, conexiones y riesgos.")
    print("------------------------------------------------------------")
    raw = input("\nIngrese la IP, dominio o rango a analizar (vacio para volver): ").strip()
    if not raw:
        return None

    if validate_target(raw):
        return raw, raw

    if is_valid_domain(raw):
        ip = resolve_domain(raw)
        if ip:
            print(f"\n[i] Dominio {raw} resuelto a {ip}")
            return ip, raw
        print(f"\n[-] No se pudo resolver el dominio {raw}")
        return "invalido"

    print("\n[-] Objetivo invalido. Use una IP, un dominio o un rango (ej. 192.168.1.1-192.168.1.10)")
    return "invalido"

def submenu_objetivo(scan_target, original_target):
    while True:
        print("\n============================================================")
        print(f" OBJETIVO: {original_target}")
        print("============================================================")
        print(" Elija el analisis a realizar sobre este objetivo.")
        print(" Sugerencia: ejecute primero un escaneo de puertos (1, 2 o 3)")
        print(" para que la deteccion de vulnerabilidades y el riesgo tengan datos.")
        print("------------------------------------------------------------")
        print(" 1. Escaneo de puertos TCP     descubre puertos y servicios abiertos")
        print(" 2. Escaneo de puertos UDP     escaneo de puertos UDP")
        print(" 3. Escaneo personalizado      tu eliges los parametros de nmap")
        print(" 4. Servicios vulnerables      busca CVEs (requiere un escaneo previo)")
        print(" 5. Conexiones sospechosas     vigila trafico saliente anomalo")
        print(" 6. Analisis DNS               resuelve y evalua el objetivo")
        print(" 7. Calculo de riesgo          consolida y puntua el riesgo (0 a 10)")
        print(" 8. Reporteria                 genera el reporte de red (JSON y PDF)")
        print(" 9. API Keys                   configura tus claves (VirusTotal o NVD)")
        print(" 0. Cambiar objetivo / volver")

        option = input("\nSeleccione una opcion: ").strip()

        if option == "1":
            tcp_scanner_menu(scan_target)
        elif option == "2":
            udp_scanner_menu(scan_target)
        elif option == "3":
            custom_scanner_menu(scan_target)
        elif option == "4":
            vulnerable_services_menu()
        elif option == "5":
            suspicious_detector_menu()
        elif option == "6":
            dns_analysis_menu(original_target)
        elif option == "7":
            risk_calculator_menu()
        elif option == "8":
            reporting_menu()
        elif option == "9":
            configure_api_keys_menu()
        elif option == "0":
            break
        else:
            print("\n[-] Opcion invalida, intente nuevamente.")

def main():
    while True:
        objetivo = pedir_objetivo()
        if objetivo is None:
            break
        if objetivo == "invalido":
            continue
        scan_target, original_target = objetivo
        submenu_objetivo(scan_target, original_target)

if __name__ == "__main__":

    main()
