
import sys

from toolkitTCU.common import findings as F
from toolkitTCU.common.reports import save_unified_report
from toolkitTCU.integration import web_facade
from toolkitTCU.integration import network_facade
from toolkitTCU.integration import integrity_facade

def print_banner():
    print("""
============================================================
            TOOLKIT TCU - SUITE DE SEGURIDAD
       Web  |  Red  |  Integridad de Archivos (FIM)
============================================================
""")

def print_main_menu():
    print("\n============================================================")
    print(" MENU PRINCIPAL")
    print("============================================================")
    print(" 1. Analisis Web          seguridad de un sitio web (headers, SSL, etc.)")
    print(" 2. Analisis de Red        escaneo de puertos, servicios y riesgos")
    print(" 3. Integridad de Archivos vigilancia de cambios en archivos (FIM)")
    print(" 4. Reporte unificado      consolida lo analizado en esta sesion")
    print(" 0. Salir")
    print("------------------------------------------------------------")
    print(" Los reportes se guardan en JSON y PDF en la carpeta reportes/")

def _safe_run(label, func):
    try:
        return func()
    except KeyboardInterrupt:
        print(f"\n[!] {label}: interrumpido por el usuario. Volviendo al menu.")
    except Exception as error:
        print(f"\n[-] Error en {label}: {error}")
    return None

def generate_unified_report():
    print("\nConsolidando los resultados ya obtenidos en esta sesion...")
    print("(no se ejecuta ningun analisis nuevo, use las opciones 1, 2 y 3 antes)")
    report = F.create_unified_report()

    net_result = _safe_run("Analisis de Red", network_facade.build_module_result)
    if net_result and net_result.get("findings"):
        F.add_module_result(report, net_result)

    int_result = _safe_run("Integridad de Archivos", integrity_facade.build_module_result)
    if int_result:
        F.add_module_result(report, int_result)

    web_result = web_facade.get_last_result()
    if web_result:
        F.add_module_result(report, web_result)
    else:
        print("[i] No hay un analisis web en esta sesion. Ejecute la opcion 1 si desea incluirlo.")

    print_unified_report(report)

    try:
        json_path, pdf_path = save_unified_report(report)
        print(f"\n[+] Reporte unificado guardado:")
        print(f"    JSON: {json_path}")
        print(f"    PDF : {pdf_path}")
    except Exception as error:
        print(f"\n[-] No se pudo guardar el reporte unificado: {error}")

def print_unified_report(report):
    summary = report["executive_summary"]
    counts = summary["severity_count"]

    print("\n============================================================")
    print(" REPORTE UNIFICADO DEL TOOLKIT")
    print("============================================================")
    print(f" Generado            : {report['metadata']['generated_at'][:19].replace('T', ' ')}")
    print(f" Modulos consolidados: {', '.join(summary['modules_run']) or 'ninguno'}")
    print(f" Puntaje global      : {summary['global_score']}/100")
    print(f" Total de hallazgos  : {summary['total_findings']}")
    print(f"   CRITICAL: {counts['CRITICAL']}  HIGH: {counts['HIGH']}  "
          f"MEDIUM: {counts['MEDIUM']}  LOW: {counts['LOW']}  INFO: {counts['INFO']}")

    for module, result in report["modules"].items():
        print("\n------------------------------------------------------------")
        print(f" [{result['display_name']}] - estado: {result['status']}")
        if result.get("summary"):
            for k, v in result["summary"].items():
                print(f"   {k}: {v}")
        print(f"   hallazgos: {len(result['findings'])}")

    findings = F.all_findings(report)
    if findings:
        print("\n------------------------------------------------------------")
        print(" DETALLE DE HALLAZGOS (por severidad)")
        print("------------------------------------------------------------")
        for f in findings:
            print(f"\n [{f['severity']}] ({f['module']}) {f['title']}")
            print(f"   {f['description']}")
            if f.get("recommendation"):
                print(f"   -> {f['recommendation']}")

def main():
    print_banner()
    while True:
        print_main_menu()
        option = input("\nSeleccione una opcion: ").strip()

        if option == "1":
            _safe_run("Analisis Web", web_facade.run_interactive)
        elif option == "2":
            _safe_run("Analisis de Red", network_facade.run_interactive)
        elif option == "3":
            _safe_run("Integridad de Archivos", integrity_facade.run_interactive)
        elif option == "4":
            generate_unified_report()
        elif option == "0":
            print("\nSaliendo del toolkit. Hasta luego.")
            break
        else:
            print("\n[-] Opcion invalida, intente nuevamente.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nSaliendo del toolkit.")
        sys.exit(0)
