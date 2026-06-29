
from toolkitTCU.web_module import orchestrator
from toolkitTCU.integration import web_facade

def available_scanners():
    return [
        {"id": sid, "name": orchestrator.SCANNER_DISPLAY_NAMES.get(sid, sid)}
        for sid in orchestrator.AVAILABLE_SCANNERS
    ]

def run_web_analysis(url, scanners_to_run=None, timeout=15, max_documents=10):
    if not url or not url.strip():
        raise ValueError("Debe indicar una URL o dominio a analizar.")

    if scanners_to_run:
        scanners_to_run = [s for s in scanners_to_run if s in orchestrator.AVAILABLE_SCANNERS]
        if not scanners_to_run:
            scanners_to_run = None

    report = orchestrator.run_analysis(
        url,
        scanners_to_run=scanners_to_run,
        timeout=timeout,
        max_documents=max_documents,
    )

    try:
        web_facade.save_reports(report)
    except Exception:
        pass

    return report
