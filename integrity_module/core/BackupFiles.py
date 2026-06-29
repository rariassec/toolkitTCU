import shutil
import os
import threading
import traceback
from datetime import datetime
from toolkitTCU.integrity_module.core.DatabaseManager import DatabaseManager
from toolkitTCU.integrity_module.utils.FileHandler import FileHandler
from toolkitTCU.integrity_module.utils.Logger import Logger
from toolkitTCU.integrity_module.utils.LoadConfig import ConfigLoader, MODULE_DIR

class BackupFiles:

    def __init__(self, db_manager:DatabaseManager, file_handler: FileHandler, log:Logger, load_config: ConfigLoader):
        self.db_manager = db_manager
        self.file_handler = file_handler
        self.load_config= load_config
        self.loaded_config = self.load_config.load_config()
        backup_cfg = self.loaded_config.get("backup", {})
        self.backup_interval = backup_cfg.get("interval_seconds", 10)
        self.backup_directory = backup_cfg.get("directory", os.path.join(MODULE_DIR, "snapshots"))
        self.log=log
        self.process=threading.Thread(target=self.run_backup_process,daemon=True)
        self.stop_event=threading.Event()
        self.running = False

    def execute_backup(self):
        try:
            backed_up=0
            failed=0
            all_paths = self.db_manager.consult_all_file_paths()
            self.log.add_to_log("BACKUP", "INFO", f"BACKUP INICIADO | Archivos a respaldar: {len(all_paths)}")
            for path in all_paths:
                if os.path.exists(path):
                    os.makedirs(self.backup_directory, exist_ok=True)
                    inode=self.file_handler.extract_file_info(path)[0]
                    if(self.db_manager.consult_file_status(inode)!= "modified"):
                        file_name = os.path.basename(path)
                        backup_directory = self.backup_directory
                        backup_path = os.path.join(backup_directory, f"{file_name}_{datetime.now().strftime('%Y%m%d%H%M%S_%f')}")
                        shutil.copy(path, backup_path)
                        if(self.store_backup(path, backup_path)):
                            backed_up+=1
                            self.log.add_to_log("BACKUP_DEBUG", "DEBUG", f"Backup OK: {file_name}")
                        else:
                            failed+=1
                            self.log.add_to_log("EXCEPTION", "ERROR", f"Backup fallo: {file_name}")
            self.log.add_to_log("BACKUP", "INFO", f"BACKUP COMPLETADO | EXITOSOS: {backed_up} | FALLIDOS: {failed} | Total: {len(all_paths)}")
        except Exception as e:
            print(f"Error en execute_backup: {e}")
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"BACKUP | Error durante el proceso: {e}")

    def execute_backup_on_created(self, path):
        try:
            backed_up=0
            failed=0
            self.log.add_to_log("BACKUP", "INFO", f"BACKUP EN CREACION INICIADO | Archivo: {path}")
            if os.path.exists(path):
                os.makedirs(self.backup_directory, exist_ok=True)
                inode=self.file_handler.extract_file_info(path)[0]
                if(self.db_manager.consult_file_status(inode)!= "modified"):
                    file_name = os.path.basename(path)
                    backup_directory = self.backup_directory
                    backup_path = os.path.join(backup_directory, f"{file_name}_{datetime.now().strftime('%Y%m%d%H%M%S_%f')}")
                    shutil.copy(path, backup_path)
                    if(self.store_backup(path, backup_path)):
                        backed_up+=1
                        self.log.add_to_log("BACKUP_DEBUG", "DEBUG", f"Backup OK: {file_name}")
                    else:
                        failed+=1
                        self.log.add_to_log("EXCEPTION", "ERROR", f"Backup fallo: {file_name}")
            self.log.add_to_log("BACKUP", "INFO", f"BACKUP EN CREACION COMPLETADO | EXITOSOS: {backed_up} | FALLIDOS: {failed}")
        except Exception as e:
            print(f"Error en execute_backup_on_created: {e}")
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"BACKUP | Error durante el proceso de creacion: {e}")

    def store_backup(self, original_path, backup_path):
        try:
            file_name=os.path.basename(original_path)
            original_info = self.db_manager.consult_inode_and_device_by_path(original_path)
            if not original_info:
                self.log.add_to_log("EXCEPTION", "ERROR", f"BACKUP STORE | Archivo original no registrado: {original_path}")
                return False
            original_inode, original_device = original_info
            backup_inode, backup_device = self.file_handler.extract_file_info(backup_path)
            hash=self.file_handler.calculate_file_hash(backup_path)
            if(self.db_manager.insert_backup_file(original_inode, original_device, backup_inode, backup_device, backup_path, hash)):
                self.log.add_to_log("BACKUP_DEBUG", "DEBUG", f"Backup OK | Archivo: {file_name} | Backup: {os.path.basename(backup_path)}")
            self.db_manager.update_hash_has_backup(original_inode, original_device)
            return True
        except Exception as e:
            print(f"Error en store_backup: {e}")
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"BACKUP STORE fallo | Original: {original_path} | Backup: {backup_path} | Error: {e}")
            return False

    def run_backup_process(self):
        while not self.stop_event.is_set():
            self.execute_backup()
            if self.stop_event.wait(self.backup_interval):
                break

    def run(self):
        try:
            self.running = True
            self.process.start()
            self.log.add_to_log("SYSTEM", "INFO", "Proceso de respaldo iniciado")
        except Exception as e:
            print(f"Error en run backup process: {e}")
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"Error al iniciar proceso de respaldo: {e}")

    def stop(self):
        self.stop_event.set()
        if self.process.is_alive():
            self.process.join()
        self.log.add_to_log("SYSTEM", "INFO", "Proceso de respaldo detenido")

