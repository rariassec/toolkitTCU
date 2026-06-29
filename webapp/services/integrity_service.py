
import json
import os
import threading
from datetime import datetime

from toolkitTCU.integrity_module.utils.LoadConfig import (
    ConfigLoader,
    DEFAULT_CONFIG_FILE,
    bootstrap_config,
    ensure_config_exists,
)

_LOCK = threading.RLock()
_SYSTEM = None

_MONITOR = {
    "running": False,
    "observer": None,
    "path_tracker": None,
    "watched": [],
}

def _build_system():
    from toolkitTCU.integrity_module.core.DatabaseManager import DatabaseManager
    from toolkitTCU.integrity_module.core.FileIntegrityChecker import FileIntegrityChecker
    from toolkitTCU.integrity_module.core.HashStorage import HashStorage
    from toolkitTCU.integrity_module.events.EventManager import EventManager
    from toolkitTCU.integrity_module.reports.ReportGenerator import ReportGenerator
    from toolkitTCU.integrity_module.utils.FileHandler import FileHandler
    from toolkitTCU.integrity_module.core.BackupFiles import BackupFiles
    from toolkitTCU.integrity_module.core.PathTracker import PathTracker
    from toolkitTCU.integrity_module.events.WatchdogEventHandler import EventHandler
    from toolkitTCU.integrity_module.utils.Logger import Logger
    from toolkitTCU.integrity_module.core.ChangesManager import ChangesManager
    from toolkitTCU.integrity_module.core.AlertManager import AlertManager
    from toolkitTCU.integrity_module.core.stats import Stats

    bootstrap_config()

    class _System:
        pass

    s = _System()
    s.load_config = ConfigLoader()
    s.log = Logger(s.load_config)
    s.db_manager = DatabaseManager(s.load_config)
    s.db_manager.set_DB()
    s.stats = Stats(s.db_manager)
    s.file_handler = FileHandler(s.db_manager, s.log)
    s.alert_manager = AlertManager(s.load_config)
    s.backup_files = BackupFiles(s.db_manager, s.file_handler, s.log, s.load_config)
    s.hash_storage = HashStorage(s.db_manager, s.file_handler, s.log, s.backup_files, s.load_config)
    s.event_manager = EventManager(s.db_manager, s.hash_storage, s.file_handler, s.log, s.load_config)
    s.changes_manager = ChangesManager(s.db_manager, s.hash_storage, s.event_manager)
    s.file_integrity_checker = FileIntegrityChecker(
        s.hash_storage, s.file_handler, s.db_manager, s.log, s.load_config)
    s.report_generator = ReportGenerator(s.db_manager, s.log, s.load_config, s.stats)
    s.path_tracker = PathTracker(s.db_manager, s.load_config)
    s.event_handler = EventHandler(
        s.event_manager, s.file_integrity_checker, s.hash_storage, s.backup_files,
        s.db_manager, s.path_tracker, s.log, s.alert_manager)
    return s

def _system():
    global _SYSTEM
    with _LOCK:
        if _SYSTEM is None:
            _SYSTEM = _build_system()
        return _SYSTEM

def _reset_system(auto_restart=True):
    global _SYSTEM
    with _LOCK:
        was_running = _MONITOR["running"]
        if was_running:
            stop_monitoring()
        _SYSTEM = None

        result = {"was_running": was_running, "restarted": False, "restart_error": None}
        if was_running and auto_restart:
            try:
                start_monitoring()
                result["restarted"] = True
            except Exception as error:
                result["restart_error"] = str(error)
        return result

ALGORITHMS = {"1": "sha256", "2": "sha512", "3": "blake2b", "4": "sha3_256"}

def _watch_paths_from_config():
    cfg = get_config()
    out = []
    for p in cfg.get("paths", []):
        out.append({"path": p, "exists": os.path.isdir(p)})
    return out

def monitoring_status():
    from toolkitTCU.integrity_module.utils.LoadConfig import MODULE_DIR
    creds = os.path.join(MODULE_DIR, "credentials.env")
    cfg = get_config()
    with _LOCK:
        return {
            "running": _MONITOR["running"],
            "watched": _watch_paths_from_config(),
            "email_enabled": cfg.get("email_enabled", False),
            "email_configured": os.path.isfile(creds),
        }

def start_monitoring():
    with _LOCK:
        if _MONITOR["running"]:
            return monitoring_status()

        s = _system()
        from toolkitTCU.integrity_module.events.Observer import file_observer

        watched = _watch_paths_from_config()
        existing = [w["path"] for w in watched if w["exists"]]
        if not existing:
            raise ValueError(
                "No hay carpetas vigiladas validas. Configure al menos una "
                "carpeta existente en la seccion de configuracion antes de "
                "iniciar el monitoreo.")

        try:
            s.hash_storage.store_default_baseline()
        except Exception as error:
            s.log.add_to_log("EXCEPTION", "ERROR", f"Baseline inicial fallo: {error}")

        try:
            s.backup_files.run()
        except Exception:
            pass
        try:
            s.path_tracker.start()
        except Exception:
            pass

        observer = file_observer(s.event_handler, s.load_config.load_config())
        observer.start()

        _MONITOR.update(running=True, observer=observer,
                        path_tracker=s.path_tracker, watched=existing)
        return monitoring_status()

def stop_monitoring():
    with _LOCK:
        observer = _MONITOR.get("observer")
        if observer is not None:
            try:
                observer.stop()
            except Exception:
                pass
        tracker = _MONITOR.get("path_tracker")
        if tracker is not None:
            try:
                tracker.stop()
            except Exception:
                pass
        if _SYSTEM is not None:
            try:
                _SYSTEM.backup_files.stop()
            except Exception:
                pass
        _MONITOR.update(running=False, observer=None, path_tracker=None, watched=[])
        return {"running": False}

def status_summary():
    with _LOCK:
        s = _system()
        date, time = s.stats.get_last_scan_date_and_time()
        return {
            "monitored_files": s.stats.get_monitored_files() or 0,
            "detected_changes": s.stats.get_detected_changes() or 0,
            "last_scan_date": date,
            "last_scan_time": time,
            "avg_scan_time": round(s.stats.get_avg_scan_time() or 0, 2),
            "system_state": s.stats.get_system_state(),
        }

def list_events():
    with _LOCK:
        return _system().db_manager.get_events_with_severity()

def list_changes():
    with _LOCK:
        return _system().db_manager.consult_all_changes()

def list_monitored_paths():
    with _LOCK:
        return _system().db_manager.consult_all_file_paths()

def store_hash(path, algorithm="sha256"):
    path = (path or "").strip()
    if not path:
        raise ValueError("Debe indicar una ruta.")
    if not os.path.exists(path):
        raise ValueError("La ruta indicada no existe.")
    if algorithm not in ALGORITHMS.values():
        algorithm = "sha256"

    with _LOCK:
        s = _system()
        if os.path.isfile(path):
            existing = s.hash_storage.consult_path_hash_existence_in_db(path)
            if existing is True:
                return {"path": path, "algorithm": algorithm, "stored": False,
                        "message": "La ruta ya tiene un hash asociado."}
            s.hash_storage.store_hash(path, algorithm)
            s.event_manager.generate_creation_event(path, "CREATED")
            return {"path": path, "algorithm": algorithm, "stored": True,
                    "message": f"Ruta protegida con {algorithm.upper()}."}

        before = set(s.db_manager.consult_all_file_paths() or [])
        s.hash_storage.store_hash(path, algorithm)
        after = set(s.db_manager.consult_all_file_paths() or [])
        new_files = after - before
        for new_file in new_files:
            s.event_manager.generate_creation_event(new_file, "CREATED")
        added = len(new_files)
        if added:
            return {"path": path, "algorithm": algorithm, "stored": True,
                    "message": f"Carpeta protegida con {algorithm.upper()}: "
                               f"{added} archivo(s) nuevo(s) agregado(s)."}
        return {"path": path, "algorithm": algorithm, "stored": False,
                "message": "La carpeta ya tiene todos sus archivos protegidos."}

def manual_detection(path, options=None):
    path = (path or "").strip()
    if not path:
        raise ValueError("Debe indicar una ruta.")
    options = options or {}
    subdirectories = bool(options.get("subdirectories"))
    hidden_files = bool(options.get("hidden_files"))
    deleted_files = bool(options.get("deleted_files"))
    automatic_report = bool(options.get("automatic_report"))

    extensions = options.get("extensions", "")
    whitelist = [e.strip().lower() for e in extensions.split(",")] if extensions else []
    whitelist.append("")

    raw_size = str(options.get("max_size", "")).strip()
    max_size = int(raw_size) if raw_size.isdigit() else None

    with _LOCK:
        s = _system()
        event, scan_session_id = s.file_integrity_checker.detect_any_hash_change(
            path, subdirectories, hidden_files, deleted_files,
            automatic_report, whitelist, max_size)

        if event == "DELETED":
            outcome, changed = "DELETED", 1
            recordable = event
        elif event == "VERIFIED" or (isinstance(event, dict) and not event):
            outcome, changed = "VERIFIED", 0
            recordable = None
        elif isinstance(event, dict):
            changed_only = {cid: c for cid, c in event.items()
                            if c.get("event_type") in ("MODIFIED", "DELETED")}
            changed = len(changed_only)
            outcome = "MODIFIED" if changed else "VERIFIED"
            recordable = changed_only if changed else None
        elif event == "MODIFIED":
            outcome, changed = "MODIFIED", 1
            recordable = event
        else:
            outcome, changed = "VERIFIED", 0
            recordable = None

        if recordable is not None:
            s.event_manager.generate_modification_event(path, recordable, scan_session_id)

        messages = {
            "VERIFIED": "Las huellas coinciden: no se detectaron cambios.",
            "DELETED": f"La ruta {path} fue eliminada.",
            "MODIFIED": f"Se detectaron cambios en {changed} archivo(s) respecto a la huella guardada.",
        }
        return {"path": path, "outcome": outcome, "changed": changed,
                "message": messages[outcome]}

def generate_report():
    from toolkitTCU.common.reports import save_module_report
    from toolkitTCU.integration import integrity_facade

    with _LOCK:
        s = _system()
        result = integrity_facade.build_module_result(s.db_manager)

    json_path, pdf_path = save_module_report(
        result, "reporte_integridad", "Reporte de Integridad de Archivos")
    return {
        "ok": True,
        "json": os.path.basename(json_path),
        "pdf": os.path.basename(pdf_path),
        "message": "Reporte de integridad generado (JSON + PDF).",
    }

def generate_graphs(static_dir):
    os.makedirs(static_dir, exist_ok=True)
    stamp = datetime.now().strftime("%H%M%S")
    files = {
        "changes_7d": f"int_7d_{stamp}.png",
        "extensions": f"int_ext_{stamp}.png",
        "tendency_30d": f"int_30d_{stamp}.png",
    }
    with _LOCK:
        s = _system()
        s.stats.changes_last_7_days_graph(save_path=os.path.join(static_dir, files["changes_7d"]))
        s.stats.afected_files_extensions_graph(save_path=os.path.join(static_dir, files["extensions"]))
        s.stats.tendency_30d_graph(save_path=os.path.join(static_dir, files["tendency_30d"]))

    generated = {}
    for key, name in files.items():
        full = os.path.join(static_dir, name)
        generated[key] = name if os.path.isfile(full) else None
    return generated

def get_config():
    ensure_config_exists()
    with open(DEFAULT_CONFIG_FILE, "r", encoding="utf-8") as fh:
        cfg = json.load(fh)
    watch = cfg.get("watch", [])
    paths = []
    recursive = True
    if watch:
        paths = watch[0].get("paths", [])
        recursive = watch[0].get("recursive", True)
    return {
        "paths": paths,
        "recursive": recursive,
        "algorithm": cfg.get("default_hashing_algorithm", "sha256"),
        "scan_interval": cfg.get("scan", {}).get("interval_seconds", 10),
        "email_enabled": cfg.get("alerts", {}).get("email_enabled", False),
    }

def update_config(paths, recursive=True, algorithm="sha256", scan_interval=10):
    ensure_config_exists()
    with open(DEFAULT_CONFIG_FILE, "r", encoding="utf-8") as fh:
        cfg = json.load(fh)
    clean = [p.strip() for p in paths if p and p.strip()]
    cfg["watch"] = [{"paths": clean, "recursive": bool(recursive)}]
    cfg.setdefault("default_baseline", {})["paths"] = clean
    if algorithm in ALGORITHMS.values():
        cfg["default_hashing_algorithm"] = algorithm
    try:
        cfg.setdefault("scan", {})["interval_seconds"] = int(scan_interval)
    except (TypeError, ValueError):
        pass
    with open(DEFAULT_CONFIG_FILE, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=4, ensure_ascii=False)
    restart = _reset_system()
    out = get_config()
    out["monitoring"] = restart
    return out

def configure_email(sender, password, receiver):
    from toolkitTCU.integrity_module.utils.AlertConfig import (
        CREDENTIALS_FILE, _set_email_enabled,
    )
    sender = (sender or "").strip()
    password = (password or "").strip()
    receiver = (receiver or "").strip()
    if not (sender and password and receiver):
        raise ValueError("Correo emisor, contrasena y destinatario son obligatorios.")
    with open(CREDENTIALS_FILE, "w", encoding="utf-8") as fh:
        fh.write(f"ALERT_EMAIL={sender}\n")
        fh.write(f"ALERT_PASSWORD={password}\n")
        fh.write(f"ALERT_TO={receiver}\n")
    _set_email_enabled(True)
    restart = _reset_system()
    if restart["was_running"] and restart["restarted"]:
        message = ("Alertas por correo configuradas y habilitadas. El monitoreo "
                   "se reinicio automaticamente para aplicarlas.")
    elif restart["was_running"]:
        message = ("Alertas configuradas, pero el monitoreo no pudo reiniciarse "
                   f"automaticamente: {restart['restart_error']}")
    else:
        message = "Alertas por correo configuradas y habilitadas."
    return {"ok": True, "message": message, "monitoring": restart}
