
import sys

from toolkitTCU.web_module.orchestrator import (
    run_analysis,
    get_sorted_findings,
    AVAILABLE_SCANNERS,
    SCANNER_DISPLAY_NAMES,
)
from toolkitTCU.web_module.utils.logger import get_logger

COLORS = {
    "CRITICAL": "\033[1;31m",
    "HIGH": "\033[1;33m",
    "MEDIUM": "\033[1;36m",
    "LOW": "\033[1;34m",
    "INFO": "\033[1;37m",
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
    "DIM": "\033[2m",
    "GREEN": "\033[1;32m",
    "CYAN": "\033[1;36m",
}

def colorize(text, color, use_color=True):
    if not use_color:
        return text
    return f"{COLORS.get(color, '')}{text}{COLORS['RESET']}"

def print_banner():
    banner = """
                    ONG SECURITY TOOL - MODULO WEB
                  Analisis pasivo de seguridad web
"""
    print(banner)

def prompt_url():
    while True:
        print()
        url = input("Ingrese la URL del sitio a analizar (ej. https://ejemplo.org): ").strip()
        if not url:
            print("  -> URL no puede estar vacia. Intente nuevamente.")
            continue
        return url

def prompt_authorization():
    print()
    print("-" * 60)
    print("ADVERTENCIA: Este modulo realiza un analisis sobre infraestructura web.")
    print("Solo debe utilizarse sobre dominios de los cuales cuente con autorizacion.")
    print("El analisis no autorizado puede constituir un delito segun la legislacion.")
    print("-" * 60)
    while True:
        answer = input("Confirma que cuenta con autorizacion? (s/n): ").strip().lower()
        if answer in ("s", "si", "y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print("  -> Respuesta invalida. Use 's' o 'n'.")

def prompt_scanners():
    print()
    print("=" * 60)
    print("SELECCION DE SCANNERS A EJECUTAR")
    print("=" * 60)
    print()
    print("Scanners disponibles:")
    print()

    for i, scanner_id in enumerate(AVAILABLE_SCANNERS, 1):
        display_name = SCANNER_DISPLAY_NAMES[scanner_id]
        print(f"  [{i}] {display_name}")

    print()
    print("Opciones rapidas:")
    print(f"  [a] Ejecutar TODOS los scanners (recomendado)")
    print(f"  [c] Cancelar y salir")
    print()
    print("Para seleccion personalizada, ingrese los numeros separados por coma.")
    print("Ejemplo: '1,2,5' ejecuta los scanners 1, 2 y 5.")
    print()

    while True:
        choice = input("Su seleccion: ").strip().lower()

        if choice in ("c", "cancelar", "q", "quit", "exit"):
            return None

        if choice in ("a", "all", "todos", ""):
            return list(AVAILABLE_SCANNERS)

        if choice.isdigit():
            num = int(choice)
            if 1 <= num <= len(AVAILABLE_SCANNERS):
                return [AVAILABLE_SCANNERS[num - 1]]
            print(f"  -> Numero fuera de rango. Use 1 a {len(AVAILABLE_SCANNERS)}.")
            continue

        try:
            numbers = [int(n.strip()) for n in choice.split(",") if n.strip()]
            if not numbers:
                raise ValueError()

            selected = []
            invalid = []
            for n in numbers:
                if 1 <= n <= len(AVAILABLE_SCANNERS):
                    scanner_id = AVAILABLE_SCANNERS[n - 1]
                    if scanner_id not in selected:
                        selected.append(scanner_id)
                else:
                    invalid.append(n)

            if invalid:
                print(f"  -> Numeros fuera de rango: {invalid}. Use 1 a {len(AVAILABLE_SCANNERS)}.")
                continue

            return selected
        except ValueError:
            print("  -> Entrada invalida. Use numeros separados por coma.")

def prompt_output_options():
    print()
    print("=" * 60)
    print("OPCIONES DE SALIDA")
    print("=" * 60)
    print()
    print("El reporte se guardara automaticamente en formato JSON y PDF")
    print("dentro de la carpeta reportes del toolkit")
    print()

    options = {
        "summary_only": False,
    }

    answer = input("Mostrar solo el resumen ejecutivo (sin detalle)? (s/n) [n]: ").strip().lower()
    if answer in ("s", "si", "y", "yes"):
        options["summary_only"] = True

    return options

def interactive_menu():
    print_banner()
    print("Bienvenido al modulo de analisis web.")
    print("Este menu lo guiara para configurar y ejecutar el analisis.")

    url = prompt_url()

    if not prompt_authorization():
        print("\nOperacion cancelada por el usuario.")
        return None

    scanners = prompt_scanners()
    if scanners is None:
        print("\nOperacion cancelada por el usuario.")
        return None

    output = prompt_output_options()

    print()
    print("=" * 60)
    print("RESUMEN DE LA SELECCION")
    print("=" * 60)
    print(f"  URL                : {url}")
    print(f"  Scanners           : {len(scanners)} seleccionados")
    for s in scanners:
        print(f"                       - {SCANNER_DISPLAY_NAMES[s]}")
    print(f"  Guardar reportes   : JSON y PDF (automatico)")
    print(f"  Solo resumen       : {'Si' if output['summary_only'] else 'No'}")
    print()

    answer = input("Iniciar analisis con esta configuracion? (s/n) [s]: ").strip().lower()
    if answer in ("n", "no"):
        print("\nOperacion cancelada por el usuario.")
        return None

    return {
        "url": url,
        "scanners": scanners,
        "output": output,
    }

def print_summary(report, use_color=True):
    meta = report["metadata"]
    summary = report["executive_summary"]
    counts = summary["severity_count"]

    print()
    print("=" * 60)
    print(colorize("RESUMEN EJECUTIVO", "BOLD", use_color))
    print("=" * 60)
    print(f"Dominio analizado    : {meta['domain']}")
    print(f"Fecha de analisis    : {meta['start_time'][:19].replace('T', ' ')}")
    print(f"Duracion total       : {meta['duration_seconds']}s")

    score = summary["global_score"]
    score_color = "CRITICAL" if score < 40 else "HIGH" if score < 60 else "MEDIUM" if score < 80 else "INFO"
    print(f"Puntaje global       : {colorize(f'{score}/100', score_color, use_color)}")
    print()
    print(f"Total de hallazgos   : {summary['total_findings']}")
    print(f"  Critico            : {colorize(str(counts['CRITICAL']), 'CRITICAL', use_color)}")
    print(f"  Alto               : {colorize(str(counts['HIGH']), 'HIGH', use_color)}")
    print(f"  Medio              : {colorize(str(counts['MEDIUM']), 'MEDIUM', use_color)}")
    print(f"  Bajo               : {colorize(str(counts['LOW']), 'LOW', use_color)}")
    print(f"  Informativo        : {colorize(str(counts['INFO']), 'INFO', use_color)}")
    print()

def print_scanner_results(report, use_color=True):
    print("=" * 60)
    print(colorize("RESULTADOS POR SCANNER", "BOLD", use_color))
    print("=" * 60)

    for scanner_id, result in report["scanners"].items():
        name = result["scanner"]
        status = result["status"]
        score = result["score"]
        n_findings = len(result["findings"])
        duration = result["duration_seconds"]

        print()
        print(colorize(f"[{name}]", "BOLD", use_color))
        print(f"  Estado    : {status}")
        print(f"  Puntaje   : {score}/100")
        print(f"  Hallazgos : {n_findings}")
        print(f"  Duracion  : {duration}s")
        if result.get("error_message"):
            print(f"  Error     : {result['error_message']}")
    print()

def print_findings(report, use_color=True):
    findings = get_sorted_findings(report)

    if not findings:
        return

    print("=" * 60)
    print(colorize("DETALLE DE HALLAZGOS", "BOLD", use_color))
    print("=" * 60)

    for i, f in enumerate(findings, 1):
        sev = f["severity"]
        print()
        print(f"{colorize(f'[{sev}]', sev, use_color)} {colorize(f['title'], 'BOLD', use_color)}")
        print(f"  ID         : {f['id']}")
        print(f"  Scanner    : {f.get('_scanner', 'N/A')}")
        print(f"  Categoria  : {f['owasp_category']}")
        print(f"  {colorize('Que significa:', 'BOLD', use_color)}")
        for line in _wrap_text(f["accessible_description"], 68):
            print(f"    {line}")

        print(f"  {colorize('Recomendacion:', 'BOLD', use_color)}")
        for line in _wrap_text(f["recommendation"], 68):
            print(f"    {line}")

        if f.get("evidence"):
            print(f"  {colorize('Evidencia:', 'BOLD', use_color)}")
            for k, v in f["evidence"].items():
                v_str = str(v)
                if len(v_str) > 60:
                    v_str = v_str[:57] + "..."
                print(f"    {k}: {v_str}")

def _wrap_text(text, width):
    import textwrap
    lines = []
    for paragraph in text.split("\n"):
        if paragraph.strip():
            lines.extend(textwrap.wrap(paragraph, width=width) or [paragraph])
        else:
            lines.append("")
    return lines

def cli_progress_callback(scanner_name, status):
    print(f"  [>] {scanner_name}: {status}")

def run_interactive_analysis():
    use_color = sys.stdout.isatty()

    config = interactive_menu()
    if config is None:
        return None

    url = config["url"]
    scanners = config["scanners"]
    summary_only = config["output"]["summary_only"]

    get_logger()

    print()
    print(f"Iniciando analisis sobre: {url}")
    print(f"Scanners solicitados: {', '.join(scanners)}")
    print()

    try:
        report = run_analysis(
            url=url,
            scanners_to_run=scanners,
            timeout=15,
            max_file_paths=None,
            max_documents=10,
            progress_callback=cli_progress_callback,
        )
    except ValueError as e:
        print(f"\nError: {e}")
        return None
    except KeyboardInterrupt:
        print("\n\nAnalisis interrumpido por el usuario.")
        return None

    print_summary(report, use_color)
    print_scanner_results(report, use_color)
    if not summary_only:
        print_findings(report, use_color)

    return report

def main():
    report = run_interactive_analysis()
    if report is None:
        sys.exit(0)

    from toolkitTCU.integration import web_facade
    web_facade.save_reports(report)

    counts = report["executive_summary"]["severity_count"]
    if counts["CRITICAL"] > 0:
        sys.exit(2)
    elif counts["HIGH"] > 0:
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
