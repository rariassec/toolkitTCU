from watchdog.events import RegexMatchingEventHandler
from toolkitTCU.integrity_module.core.DatabaseManager import DatabaseManager
from toolkitTCU.integrity_module.core.FileIntegrityChecker import FileIntegrityChecker
from toolkitTCU.integrity_module.core.HashStorage import HashStorage
from toolkitTCU.integrity_module.events.EventManager import EventManager
import os
import re
import time
import traceback
from toolkitTCU.integrity_module.core.BackupFiles import BackupFiles
from toolkitTCU.integrity_module.core.PathTracker import PathTracker
from toolkitTCU.integrity_module.utils.Logger import Logger
from toolkitTCU.integrity_module.core.AlertManager import AlertManager

NOISE_PATTERNS = [
    re.compile(r".*\.sw[a-p]$"),
    re.compile(r".*~$"),
    re.compile(r".*/#[^/]*#$"),
    re.compile(r".*/\.#[^/]*$"),
    re.compile(r".*\.kate-swp$"),
]

TEMP_PATTERNS = [
    re.compile(r".*\.goutputstream.*"),
    re.compile(r".*___jb_tmp___.*"),
    re.compile(r".*___jb_old___.*"),
    re.compile(r".*\.tmp$"),
    re.compile(r".*\.part$"),
    re.compile(r".*\.crdownload$"),
    re.compile(r".*/4913$"),
]

class EventHandler(RegexMatchingEventHandler):

    def __init__(self, event_manager: EventManager, file_integrity_checker: FileIntegrityChecker, hash_storage: HashStorage, backup_files: BackupFiles, db_manager: DatabaseManager, path_tracker: PathTracker, log: Logger, alert_manager: AlertManager):
        super().__init__(
             ignore_directories=True,
             regexes=[r'.*'],
             ignore_regexes=[]
        )
        self.file_integrity_checker = file_integrity_checker
        self.event_manager = event_manager
        self.hash_storage = hash_storage
        self.file_handler = hash_storage.file_handler
        self.backup_files = backup_files
        self.db_manager = db_manager
        self.pending_delete = None
        self.path_tracker = path_tracker
        self.log = log
        self.alert_manager = alert_manager
        self._alerted = {}

    def _is_noise(self, path):
        return any(p.match(path) for p in NOISE_PATTERNS)

    def _is_temp_artifact(self, path):
        return any(p.match(path) for p in TEMP_PATTERNS)

    def _ignored(self, path):
        return self._is_noise(path) or self._is_temp_artifact(path)

    def _register_modification(self, path):
        if not os.path.isfile(path):
            return False
        info = self.db_manager.consult_all_file_info_by_path(path)
        if not info:
            return False
        stored_inode = info.get("inode")
        baseline_hash = info.get("hash")
        algorithm = self.db_manager.consult_file_algorithm(stored_inode) or "sha256"
        current_hash = self.file_handler.calculate_file_hash(path, algorithm)
        if not current_hash or current_hash == baseline_hash:
            return False
        if self._alerted.get(path) == current_hash:
            return False
        self._alerted[path] = current_hash
        new_inode, new_device = self.file_handler.extract_file_info(path)
        severity = self.event_manager.get_severity(path, "MODIFIED")
        self.db_manager.insert_modification_event(new_inode, new_device, baseline_hash, current_hash, path, "MODIFIED", severity)
        self.db_manager.update_file_identity_by_path(path, new_inode, new_device, "modified")
        print(f"[+] WARNING: El archivo ha sido modificado: {path}")
        self.alert_manager.send_alert(
            severity or "WARNING",
            "Archivo Modificado",
            f"Se detecto modificacion en: {path}"
        )
        return True

    def _register_creation(self, path):
        if not os.path.isfile(path):
            return False
        if self.db_manager.consult_file_existence_by_path(path):
            return self._register_modification(path)
        if self.hash_storage.consult_path_hash_existence_in_db(path) != False:
            return False
        self.hash_storage.store_hash(path)
        self.event_manager.generate_creation_event(path, "CREATED")
        severity = self.event_manager.get_severity(path, "CREATED")
        print(f"[+] El hash se ha guardado correctamente: {path}")
        self.alert_manager.send_alert(
            severity or "INFO",
            "Archivo Creado",
            f"Se creo un archivo nuevo en la ruta vigilada: {path}"
        )
        return True

    def _register_rename(self, src, dest):
        info = self.db_manager.consult_all_file_info_by_path(src)
        if not info:
            return False
        if not os.path.isfile(dest):
            return False
        new_inode, new_device = self.file_handler.extract_file_info(dest)
        self.db_manager.update_file_path_by_path(src, dest, new_inode, new_device)
        severity = self.event_manager.get_severity(dest, "MODIFIED")
        print(f"[+] WARNING: Archivo renombrado: {src} -> {dest}")
        self.alert_manager.send_alert(
            severity or "WARNING",
            "Archivo Renombrado",
            f"Se renombro/movio un archivo vigilado: {src} -> {dest}"
        )
        return True

    def on_created(self, event):
        try:
            path = event.src_path
            if self._ignored(path):
                return
            time.sleep(0.5)
            if self.db_manager.consult_file_existence_by_path(path):
                self._register_modification(path)
                return
            self._register_creation(path)
        except Exception as e:
            print(f"Error en on_created de Watchdog: {e}")
            print(traceback.format_exc())

    def on_modified(self, event):
        try:
            path = event.src_path
            if self._ignored(path):
                return
            self._register_modification(path)
        except Exception as e:
            print(f"Error en on_modified de Watchdog: {e}")
            print(traceback.format_exc())

    def on_moved(self, event):
        try:
            src = event.src_path
            dest = getattr(event, "dest_path", None)
            if not dest:
                return
            time.sleep(0.3)

            if self.db_manager.consult_file_existence_by_path(dest):
                self._register_modification(dest)
                return

            if self.db_manager.consult_file_existence_by_path(src):

                if self._ignored(dest):
                    return
                self._register_rename(src, dest)
                return

            if not self._ignored(dest):
                self._register_creation(dest)
        except Exception as e:
            print(f"Error en on_moved de Watchdog: {e}")
            print(traceback.format_exc())

    def on_deleted(self, event):
        try:
            if self._ignored(event.src_path):
                return
            res = self.db_manager.consult_inode_and_device_by_path(event.src_path)
            if not res:
                return
            inode, device = res
            self.pending_delete = (inode, event.src_path)
            found = self.path_tracker.search_file_in_disk([inode])
            if(found and inode in found and found[inode] != event.src_path):
                self.pending_delete = None
                print(f"\n[+] El archivo {event.src_path} ha sido encontrado en el sistema con el mismo inodo, no se genera evento de eliminacion.\n")
                self.log.add_to_log("EVENT", "INFO", f"MOVED | Ruta anterior: {event.src_path} | Nueva ruta: {found[inode]} | Inode: {inode}")
                return
            else:
                time.sleep(1.5)

                if self.pending_delete and self.pending_delete[0] == inode:
                    self.pending_delete = None
                    print(f"ELIMINADO: {event.src_path}")
                    self.hash_storage.execute_file_update_status(inode, "deleted")
                    self.event_manager.file_deleted_event(event.src_path, event.event_type)
                    severity = self.event_manager.get_severity(event.src_path, "DELETED")
                    self.alert_manager.send_alert(
                        severity or "CRITICAL",
                        "Archivo Eliminado",
                        f"Se elimino: {event.src_path}"
                    )
        except Exception as e:
            print(f"Error en on_deleted de Watchdog: {e}")
            print(traceback.format_exc())
