import os
from toolkitTCU.integrity_module.core.HashStorage import HashStorage
from toolkitTCU.integrity_module.utils.FileHandler import FileHandler
from toolkitTCU.integrity_module.core.DatabaseManager import DatabaseManager
from toolkitTCU.integrity_module.utils.Logger import Logger
from pathlib import Path
import traceback
from datetime import datetime
import threading
from toolkitTCU.integrity_module.utils.LoadConfig import ConfigLoader
class FileIntegrityChecker:

    def __init__(self, hash_storage: HashStorage, file_handler: FileHandler, db_manager: DatabaseManager, log:Logger, config: ConfigLoader ):
        self.hashing_algorithm = "sha256"
        self.hash_storage = hash_storage
        self.file_handler=file_handler
        self.db_manager=db_manager
        self.log=log
        self.config_loader = config
        self.config = config.load_config()
        self.baseline_paths=self.config.get("default_baseline", {}).get("paths", [])
        self.starting_process=threading.Thread(target=self.detect_changes_at_start, daemon=True)

    def is_hidden(self, path):
     p = Path(path)
     return p.name.startswith('.')

    def exclude_subdirectories(self, root_path, all_changes):
        try:
            files_to_delete=[]
            for change_id, change in all_changes.items():
                path_file=change["file_path"]
                dirname=os.path.dirname(path_file)
                if dirname!=root_path:
                    files_to_delete.append(change_id)

            if files_to_delete:
                for change_id in files_to_delete:
                    del all_changes[change_id]
            return all_changes
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"EXCLUDE SUBDIRECTORIES fallo | Error: {e}")
            return []

    def exclude_hidden_files(self, all_changes):
        try:

            files_to_delete=[]
            for change_id, change in all_changes.items():
                path_file=change["file_path"]
                if self.is_hidden(path_file):
                    files_to_delete.append(change_id)

            for change_id in files_to_delete:
                del all_changes[change_id]
            return all_changes
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"EXCLUDE HIDDEN FILES fallo | Error: {e}")
            return []

    def exclude_deleted_files(self, all_changes):
        try:
            files_to_delete=[]
            for change_id, change in all_changes.items():
                event_type=change["event_type"]
                if event_type=="DELETED":
                    files_to_delete.append(change_id)

            for change_id in files_to_delete:
                del all_changes[change_id]
            return all_changes
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"EXCLUDE DELETED FILES fallo | Error: {e}")
            return []

    def exclude_files_not_matching_extensions(self, whitelist, all_changes):
        try:
            normalized = {e.strip().lower().lstrip(".") for e in (whitelist or []) if e and e.strip()}
            if not normalized:
                return all_changes
            files_to_delete=[]
            for change_id, change in all_changes.items():
                path_file=change["file_path"]
                file_extension=os.path.splitext(path_file)[1].lower()
                file_extension=file_extension.lstrip(".")
                if file_extension not in normalized:
                    files_to_delete.append(change_id)

            for change_id in files_to_delete:
                del all_changes[change_id]

            return all_changes
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"EXCLUDE FILES NOT MATCHING EXTENSIONS fallo  | Error: {e}")
            return all_changes

    def exclude_files_not_matching_size(self, size, all_changes):
        try:
            files_to_delete=[]
            max_size= size * 1024 * 1024
            for change_id, change in all_changes.items():
                path_file=change["file_path"]
                if not os.path.exists(change["file_path"]):
                    info_deleted_file=self.db_manager.consult_all_info_backup_file_by_path(change["file_path"])
                    if info_deleted_file:
                        path_file=info_deleted_file["file_path"]
                    else:
                        continue
                file_size=os.path.getsize(path_file)
                if not file_size <= max_size:
                    files_to_delete.append(change_id)

            for change_id in files_to_delete:
                del all_changes[change_id]
            return all_changes
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"EXCLUDE FILES NOT MATCHING SIZE fallo | Error: {e}")
            return []

    def verify_hash_changes_in_directory(self, directory_path):
        try:
            files_hashes = {}
            visited_paths = set()
            files_in_db=set(self.db_manager.consult_all_file_paths() or [])

            for root, dirs, files in os.walk(directory_path):
                for file in files:
                    full_path = os.path.join(root,file)
                    visited_paths.add(full_path)
                    if full_path not in files_in_db:
                        continue
                    db_info=self.db_manager.consult_all_file_info_by_path(full_path)
                    if not db_info:
                        continue
                    algorithm=self.db_manager.consult_file_algorithm(db_info["inode"]) or "sha256"
                    files_hashes[full_path] = self.file_handler.calculate_file_hash(full_path, algorithm)

            deleted_files=self.db_manager.consult_all_deleted_files()

            for deleted_file in deleted_files:
                path=deleted_file["file_path"]
                hash=deleted_file["hash"]
                if directory_path == os.path.dirname(path) and path not in visited_paths:
                    files_hashes[path] = hash

            return files_hashes
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"VERIFY DIR HASH fallo | Directorio: {directory_path} | Error: {e}")
            return {}

    def detect_deletion(self, path):
        res = self.db_manager.consult_inode_and_device_by_path(path)
        if not res:
            return False
        inode, device = res
        try:
            self.db_manager.update_file_hash_status(inode, "deleted")
            return True
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"DETECT DELETION fallo | Ruta: {path} | Error: {e}")
            return False

    def detect_file_hash_changes(self, path):
        try:
            all_file_info=self.db_manager.consult_all_file_info_by_path(path)
            if not all_file_info:
                return ""
            if all_file_info.get("status")== "deleted":
                return "DELETED"
            if not os.path.isfile(path):
                self.db_manager.update_file_hash_status(all_file_info["inode"], "deleted")
                return "DELETED"
            stored_inode=all_file_info["inode"]
            old_hash=all_file_info.get("hash")
            algo=self.db_manager.consult_file_algorithm(stored_inode) or "sha256"
            new_hash = self.file_handler.calculate_file_hash(path, algo)

            if old_hash == new_hash:
                self.db_manager.update_file_hash_status(stored_inode,"verified")
                return "VERIFIED"
            else:
                self.db_manager.update_file_hash_status(stored_inode, "modified")
                return "MODIFIED"
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"DETECT FILE HASH fallo | Ruta: {path} | Error: {e}")
            return ""

    def detect_directory_hash_changes(self, path):
        try:
            files_checked=0
            files_changed=0
            all_changes = {}
            change_id = 0
            file_hashes = self.verify_hash_changes_in_directory(path)
            for file_path, hash_value in file_hashes.items():
                files_checked+=1
                change_id += 1
                change = {}
                all_file_info=self.db_manager.consult_all_file_info_by_path(file_path)
                if not all_file_info:
                    continue
                if all_file_info["status"] == "deleted":
                    change["inode"] = all_file_info["inode"]
                    change["device"] = all_file_info["device"]
                    change["old_hash"] = all_file_info["hash"]
                    change["new_hash"] = all_file_info["hash"]
                    change["file_path"] = file_path
                    change["event_type"] = "DELETED"
                    files_changed+=1
                    all_changes[change_id] = change
                else:
                    change["inode"] = all_file_info["inode"]
                    change["device"] = all_file_info["device"]
                    change["old_hash"] = all_file_info.get("hash")
                    change["new_hash"] = hash_value
                    change["file_path"] = file_path
                    change["event_type"] = "N/A"

                    if change["old_hash"] not in ("", None):
                        if change["old_hash"] == change["new_hash"]:
                            change["event_type"] = "VERIFIED"
                            self.log.add_to_log("DEBUG", "DEBUG", f"VERIFIED | Archivo: {os.path.basename(file_path)}")
                        elif change["old_hash"] != change["new_hash"]:
                            change["event_type"] = "MODIFIED"
                            files_changed+=1

                    all_changes[change_id] = change

            return all_changes, files_checked, files_changed
        except Exception as e:
            self.log.add_to_log("EXCEPTION", "ERROR", f"DETECT DIR HASH fallo | Directorio: {path} | Error: {e}")
            print(traceback.format_exc())
            return {}, 0, 0

    def detect_any_hash_change(self, path, subdirectories, hidden_files, deleted_files, automatic_reports, extensions, file_size):
        started_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        files_checked=0
        files_changed=0
        try:
            file_existence=self.db_manager.consult_file_existence_by_path(path)
            if(os.path.isfile(path) or (file_existence and not os.path.isfile(path) and not os.path.isdir(path))):
                flag=self.detect_file_hash_changes(path)
                ended_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                files_changed= 1 if flag == "MODIFIED" or flag=="DELETED" else 0
                self.db_manager.insert_scan_session("MANUAL", started_at, ended_at, 1, files_changed, "COMPLETED")
                scan_session_id=self.db_manager.get_last_scan_session_id()
                return flag, scan_session_id
            else:
                directory_changes, files_checked, files_changed=self.detect_directory_hash_changes(path)
                if subdirectories == False:
                    directory_changes=self.exclude_subdirectories(path, directory_changes)
                if hidden_files == False:
                    directory_changes=self.exclude_hidden_files(directory_changes)
                if deleted_files == False:
                    directory_changes=self.exclude_deleted_files(directory_changes)
                if extensions:
                    directory_changes=self.exclude_files_not_matching_extensions(extensions, directory_changes)
                if file_size != None:
                    directory_changes= self.exclude_files_not_matching_size(file_size, directory_changes)
                ended_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                self.db_manager.insert_scan_session("MANUAL", started_at, ended_at, files_checked, files_changed, "COMPLETED")
                scan_session_id=self.db_manager.get_last_scan_session_id()
                return directory_changes, scan_session_id
        except Exception as e:
            ended_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(traceback.format_exc())
            self.db_manager.insert_scan_session("MANUAL", started_at, ended_at, files_checked, files_changed, "FAILED")
            self.log.add_to_log("EXCEPTION", "ERROR", f"DETECT ANY HASH fallo | Ruta: {path} | Error: {e}")
            return {}, None

    def detect_changes_at_start(self):
        from toolkitTCU.integrity_module.events.EventManager import EventManager
        event_manager=EventManager(self.db_manager, self.hash_storage, self.file_handler, self.log, self.config_loader)
        for path in self.baseline_paths:
            event, scan_session_id=self.detect_any_hash_change(path, subdirectories=True, hidden_files=True, deleted_files=True, automatic_reports=True, extensions=[], file_size=1000000000)

            event_manager.generate_modification_event(path, event, scan_session_id)

    def begin_detect_changes_at_start(self):
        self.starting_process.start()
