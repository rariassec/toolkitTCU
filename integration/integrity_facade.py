
from toolkitTCU.common import findings as F
from toolkitTCU.integrity_module.utils.LoadConfig import ConfigLoader
from toolkitTCU.integrity_module.core.DatabaseManager import DatabaseManager

_RELEVANT_EVENTS = {"CREATED", "MODIFIED", "DELETED"}

_EVENT_DESCRIPTION = {
    "CREATED": "Se creó un archivo nuevo en una ruta monitoreada.",
    "MODIFIED": "Se modificó el contenido de un archivo monitoreado.",
    "DELETED": "Se eliminó un archivo monitoreado.",
}

_EVENT_RECOMMENDATION = {
    "CREATED": "Verifique que la creación del archivo sea legítima; si no, "
               "investigue su origen.",
    "MODIFIED": "Confirme que el cambio fue autorizado; de lo contrario, "
                "restaure desde respaldo e investigue.",
    "DELETED": "Confirme que la eliminación fue intencional; de lo contrario, "
               "restaure desde respaldo e investigue.",
}

def _get_db_manager():
    config = ConfigLoader()
    return DatabaseManager(config)

def collect_findings(db_manager=None):
    if db_manager is None:
        db_manager = _get_db_manager()

    findings = []
    for event in db_manager.get_events_with_severity():
        event_type = str(event.get("event_type", "")).upper()
        if event_type not in _RELEVANT_EVENTS:
            continue
        findings.append(F.create_finding(
            module=F.MODULE_INTEGRITY,
            finding_id=f"INT-EVT-{event.get('event_id')}",
            title=f"Archivo {event_type.lower()}: {event.get('file_path')}",
            severity=event.get("severity"),
            category=f"Cambio de integridad ({event_type})",
            description=(
                f"{_EVENT_DESCRIPTION.get(event_type, 'Cambio detectado.')} "
                f"Ruta: {event.get('file_path')} "
                f"(detectado: {event.get('timestamp')})."
            ),
            recommendation=_EVENT_RECOMMENDATION.get(
                event_type, "Revise el cambio detectado."
            ),
            evidence={
                "archivo": event.get("file_path"),
                "tipo_evento": event_type,
                "timestamp": event.get("timestamp"),
            },
        ))
    return findings

def build_module_result(db_manager=None):
    if db_manager is None:
        db_manager = _get_db_manager()

    result = F.create_module_result(F.MODULE_INTEGRITY)
    result["findings"] = collect_findings(db_manager)
    try:
        result["summary"] = {
            "archivos_monitoreados": db_manager.get_total_files_monitored(),
            "cambios_detectados": db_manager.get_detected_changes(),
        }
    except Exception:
        result["summary"] = {}
    return result

def run_interactive():
    from toolkitTCU.integrity_module.main import FileIntegritySystem
    system = FileIntegritySystem()
    system.run()
    return build_module_result(system.db_manager)
