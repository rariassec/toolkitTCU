import os
from toolkitTCU.integrity_module.utils import FileHandler
from toolkitTCU.integrity_module.core.DatabaseManager import DatabaseManager
from toolkitTCU.integrity_module.utils.Logger import Logger
import traceback
from toolkitTCU.integrity_module.utils.LoadConfig import ConfigLoader
import fnmatch

class EventManager:

    def __init__(self, db_manager: DatabaseManager, hash_storage, file_handler: FileHandler, log: Logger, load_config:ConfigLoader):
        self.hashing_algorithm="sha256"
        self.db_manager=db_manager
        self.hash_storage=hash_storage
        self.file_handler=file_handler
        self.log=log
        self.load_config=load_config
        self.loaded_config=self.load_config.load_config()

    def get_severity(self, path, event_type):
        event_type=event_type.upper()
        if event_type == "VERIFIED":
            return
        severity_level=self.loaded_config.get("severity_levels", {}).get(event_type, {})
        norm_path = os.path.normpath(path)

        for severity, paths in severity_level.items():
            for p in paths:
                if p == "*":
                    return severity
                p_norm = os.path.normpath(p)
                if (fnmatch.fnmatch(norm_path, p)
                        or norm_path == p_norm
                        or norm_path.startswith(p_norm + os.sep)):
                    return severity

        return self.loaded_config.get("default_severity", "MEDIUM")

    def generate_creation_event(self, path, event_type, algorithm=None):
            try:
                algo=algorithm or self.hashing_algorithm
                if(os.path.isfile(path)):
                    if(self.file_creation_event(path, event_type, algo)):
                         return True
                else:
                    self.directory_creation_event(path, algo)
                    if(self.db_manager.consult_new_events_existence()):
                         return True
            except Exception as e:
                 print(f"Error en generate_creation_event: {e}")
                 print(traceback.format_exc())
                 self.log.add_to_log("EXCEPTION", "ERROR", f"CREATED | Ruta: {path} | Error: {e} | Estado: Excepcion no controlada")
                 return False

    def directory_creation_event(self, directory_path, algorithm=None):
         try:

            algo = algorithm or self.hashing_algorithm
            all_hashes=self.file_handler.calculate_directory_hashes(directory_path, algo)
            for file in all_hashes:
                path=file[0]
                hash=file[1]
                file_info= self.file_handler.extract_file_info(path)
                inode=file_info[0]
                device=file_info[1]
                severity=self.get_severity(path, "CREATED")
                self.db_manager.insert_creation_event(inode, device,hash,path, severity)
            self.log.add_to_log("EVENT", "INFO", f"CREATED DIR | Ruta: {directory_path} | Archivos procesados: {len(all_hashes)} | Algoritmo: {algo} | Estado: Exito")
         except Exception as e:
              print(f"Error en directory_creation_event: {e}")
              print(traceback.format_exc())
              self.log.add_to_log("EXCEPTION", "ERROR", f"CREATED DIR fallo | Ruta: {directory_path} | Error: {e} | Estado: Fallo al procesar directorio")

    def file_creation_event(self, file_path, event_type, algorithm=None):
            try:
                algo=algorithm or self.hashing_algorithm
                hash=self.file_handler.calculate_file_hash(file_path, algo)
                file_info= self.file_handler.extract_file_info(file_path)
                inode=file_info[0]
                device=file_info[1]
                severity=self.get_severity(file_path, event_type)
                self.db_manager.insert_creation_event(inode, device,hash,file_path, severity)
                self.log.add_to_log("EVENT", "INFO", f"CREATED FILE | Ruta: {file_path} | Inode: {inode} | Device: {device} | Hash: {hash[:16]}... | Algoritmo: {algo} | Estado: Exito")
                return True
            except Exception as e:
                  print(f"Error en file_creation_event: {e}")
                  print(traceback.format_exc())
                  self.log.add_to_log("EXCEPTION", "ERROR", f"CREATED FILE fallo | Ruta: {file_path} | Error: {e} | Estado: No se pudo insertar el evento")
                  return False

    def generate_modification_event(self, path, event, scan_session_id=None):
            try:
                event_logged=False
                file_existence=self.db_manager.consult_file_existence_by_path(path)
                if(os.path.isfile(path) ):
                     if(self.file_modification_event(path, event, scan_session_id)):
                        event_logged=True
                elif file_existence and not os.path.isfile(path):
                         all_file_info=self.db_manager.consult_all_file_info_by_path(path)
                         if not all_file_info:
                             return event_logged
                         inode=all_file_info["inode"]
                         device=all_file_info["device"]
                         old_hash=all_file_info["hash"]
                         new_hash=all_file_info["hash"]
                         severity=self.get_severity(path, "MODIFIED")
                         self.db_manager.insert_modification_event(inode, device, old_hash, new_hash, path, event, severity)
                         self.db_manager.insert_session_events(scan_session_id, self.db_manager.get_last_modified_event_id())
                else:
                    if not isinstance(event, dict):
                        return event_logged
                    self.directory_modification_event(event, scan_session_id)
                    if(self.db_manager.consult_new_events_existence()):
                        event_logged=True
                if not (event_logged):
                        self.log.add_to_log("EXCEPTION", "ERROR", f"MODIFICATION fallo | Ruta: {path} | Estado: Fallo en insercion del evento")
            except Exception as e:
                print(f"Error en generate_modification_event: {e}")
                print(traceback.format_exc())
                self.log.add_to_log("EXCEPTION", "ERROR", f"MODIFICATION | Ruta: {path} | Error: {e} | Estado: Excepcion no controlada")
                return False

    def file_modification_event(self, path, event_type, scan_session_id=None):
        try:
            file_info=self.file_handler.extract_file_info(path)
            inode=file_info[0]
            device=file_info[1]
            old_hash=self.hash_storage.consult_hash(path)
            algorithm=self.db_manager.consult_file_algorithm(inode)
            new_hash=self.file_handler.calculate_file_hash(path, algorithm)
            severity=self.get_severity(path, "MODIFIED")
            self.db_manager.insert_modification_event(inode, device, old_hash, new_hash, path, event_type, severity)
            self.db_manager.insert_session_events(scan_session_id, self.db_manager.get_last_modified_event_id())
            self.log.add_to_log("EVENT", "WARNING" if event_type == "MODIFIED" else "INFO", f"{event_type} FILE | Ruta: {path} | Inode: {inode} | Hash almacenado en baseline: {old_hash[:16]}... | Hash nuevo: {new_hash[:16]}... | Algoritmo: {algorithm} | Estado: Exito")
            return True
        except Exception as e:
            print(f"Error en file_modification_event: {e}")
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"{event_type} FILE fallo | Ruta: {path} | Error: {e} | Estado: Fallo al procesar modificacion")
            return False

    def directory_modification_event(self, all_changes, scan_session_id=None):
         try:
            dir_name= None
            for dict in all_changes.values():
                if dict["old_hash"] != "" and dict["event_type"] !="":
                    inode=dict["inode"]
                    device=dict["device"]
                    old_hash=dict["old_hash"]
                    new_hash=dict["new_hash"]
                    event_type=dict["event_type"]
                    file_path=dict["file_path"]
                    if dir_name is None:
                         dir_name = os.path.dirname(file_path)
                    severity=self.get_severity(file_path, event_type)
                    self.db_manager.insert_modification_event(inode, device, old_hash, new_hash, file_path, event_type, severity)
                    self.db_manager.insert_session_events(scan_session_id, self.db_manager.get_last_modified_event_id())
                    self.log.add_to_log("EVENT", "WARNING" if event_type == "MODIFIED" else "INFO", f"{event_type} | Archivo: {os.path.basename(file_path)} | Hash anterior: {old_hash[:16]}... | Hash nuevo: {new_hash[:16]}... | Inode: {inode}")
                else:
                     continue

            self.log.add_to_log("EVENT", "INFO", f"MODIFIED DIR | Directorio: {dir_name} | Total archivos: {len(all_changes)} | Estado: Exito")
         except Exception as e:
                print(f"Error en directory_modification_event: {e}")
                print(traceback.format_exc())
                self.log.add_to_log("EXCEPTION", "ERROR", f"MODIFIED DIR fallo | Error: {e}")
                return False

    def generate_updated_event(self, path, event):
           try:
                event_logged=False
                if(os.path.isfile(path) and event is None):
                    if(self.file_updated_event(path)):
                         event_logged=True
                else:
                    self.directory_updated_event(event)
                    if(self.db_manager.consult_new_events_existence()):
                        event_logged=True
                if(event_logged):
                     self.log.add_to_log("EVENT", "INFO", f"UPDATED | Ruta: {path} | Tipo: {'Archivo' if os.path.isfile(path) else 'Directorio'} | Estado: Exito")
                else:
                     self.log.add_to_log("EXCEPTION", "ERROR", f"UPDATED fallo | Ruta: {path} | Estado: Fallo en actualizacion")
           except Exception as e:
                print(f"Error en generate_updated_event: {e}")
                print(traceback.format_exc())
                self.log.add_to_log("EXCEPTION", "ERROR", f"UPDATED | Ruta: {path} | Error: {e} | Estado: Excepcion no controlada")
                return False

    def directory_updated_event(self, all_changes):
        try:
            dir_name = None
            for dict in all_changes.values():
                if dict["old_hash"] != "":
                    inode=dict["inode"]
                    device=dict["device"]
                    old_hash=dict["old_hash"]
                    new_hash=dict["new_hash"]
                    file_path=dict["file_path"]
                    if dir_name is None:
                        dir_name = os.path.dirname(file_path)
                    self.db_manager.insert_updated_event(inode, device, old_hash, new_hash, file_path)
                    self.log.add_to_log("EVENT", "INFO", f"UPDATED FILE | Archivo: {os.path.basename(file_path)} | Hash anterior: {old_hash[:16]}... | Hash nuevo: {new_hash[:16]}... | Inode: {inode}")
                else:
                    continue
            self.log.add_to_log("EVENT", "INFO", f"UPDATED DIR | Directorio: {dir_name} | Total archivos: {len(all_changes)} | Estado: Exito")
        except Exception as e:
             print(f"Error en directory_updated_event: {e}")
             print(traceback.format_exc())
             self.log.add_to_log("EXCEPTION", "ERROR", f"UPDATED DIR fallo | Error: {e} | Estado: Excepcion al procesar directorio")

    def file_updated_event(self, path):
            try:
                old_hash=self.hash_storage.consult_hash(path)
                new_hash=self.file_handler.calculate_file_hash(path)
                file_info= self.file_handler.extract_file_info(path)
                inode=file_info[0]
                device=file_info[1]
                if(self.db_manager.insert_updated_event(inode, device, old_hash, new_hash, path)):
                    self.log.add_to_log("EVENT", "INFO", f"UPDATED FILE | Ruta: {path} | Inode: {inode} | Hash anterior: {old_hash[:16]}... | Hash nuevo: {new_hash[:16]}... | Estado: Exito")
                    return True
                else:
                    return False
            except Exception as e:
                print(f"Error en file_updated_event: {e}")
                print(traceback.format_exc())
                self.log.add_to_log("EXCEPTION", "ERROR", f"UPDATED FILE fallo | Ruta: {path} | Error: {e} | Estado: Fallo al actualizar hash")
                return False

    def file_deleted_event(self, path, event_type):
        try:
            full_info = self.db_manager.obtain_full_info_by_path(path)
            if not full_info:
                self.log.add_to_log("EVENT", "INFO", f"DELETED | Ruta: {path} | Estado: archivo no registrado, se omite")
                return False
            inode=full_info['inode']
            device=full_info['device']
            old_hash=full_info['hash']
            severity=self.get_severity(path,event_type)
            if(self.db_manager.insert_deleted_event(path, inode, device, old_hash, severity)):
                self.log.add_to_log("EVENT", "WARNING", f"DELETED | Ruta: {path} | Inode: {inode} | Device: {device} | Ultimo hash: {old_hash[:16]}... | Estado: Exito")
                return True
            else:
                self.log.add_to_log("EXCEPTION", "ERROR", f"DELETED fallo | Ruta: {path} | Inode: {inode} | Estado: Fallo en insercion del evento")
                return False
        except Exception as e:
                print(f"Error en file_deleted_event: {e}")
                print(traceback.format_exc())
                self.log.add_to_log("EXCEPTION", "ERROR", f"DELETED | Ruta: {path} | Error: {e} | Estado: Excepcion no controlada")
                return False

    def backup_event(self, path):
        try:
            old_hash=self.hash_storage.consult_hash(path)
            new_hash=self.file_handler.calculate_file_hash(path)
            file_info= self.file_handler.extract_file_info(path)
            inode=file_info[0]
            device=file_info[1]
            self.db_manager.insert_backup_event(inode, device, old_hash, new_hash, path)
            self.log.add_to_log("BACKUP", "INFO", f"BACKUP | Ruta: {path} | Inode: {inode} | Hash respaldado: {old_hash[:16]}... | Estado: Exito")
        except Exception as e:
                print(f"Error en backup_event: {e}")
                print(traceback.format_exc())
                self.log.add_to_log("EXCEPTION", "ERROR", f"BACKUP fallo | Ruta: {path} | Error: {e} | Estado: Fallo al respaldar")
                return False

