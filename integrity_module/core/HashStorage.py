import os
from toolkitTCU.integrity_module.core.DatabaseManager import DatabaseManager
from toolkitTCU.integrity_module.utils.FileHandler import FileHandler
from toolkitTCU.integrity_module.utils.Logger import Logger
from toolkitTCU.integrity_module.core.BackupFiles import BackupFiles
from toolkitTCU.integrity_module.utils.LoadConfig import ConfigLoader
import threading
import traceback

class HashStorage:

    def __init__(self, db_manager: DatabaseManager, file_handler: FileHandler, log: Logger, backup_files:BackupFiles, config:ConfigLoader):
        self.db_manager = db_manager
        self.file_handler = file_handler
        self.config = config.load_config()
        self.hashing_algorithm = self.config.get("default_hashing_algorithm", "sha256")
        self.default_baseline = self.config.get("default_baseline", {}).get("paths", [])
        self.log = log
        self.backup_files = backup_files
        self.process_storing = threading.Thread(target=self.store_default_baseline, daemon=True)

    def store_default_baseline(self):
        for path in self.default_baseline:
            existence = self.consult_path_hash_existence_in_db(path)
            if not existence:
                self.store_hash(path, self.hashing_algorithm)
                print(f"[+] Archivo {path} agregado a la DB")
            else:
                print(f"[+] Ya existe el archivo {path} en la DB")

    def start_store_default_baseline(self):
        try:
            self.process_storing.start()
            self.log.add_to_log("SYSTEM", "INFO", "Proceso de almacenamiento inicial de baseline iniciado")
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"Error al iniciar proceso de almacenamiento inicial de baseline: {e}")

    def store_hash(self, input_path, algorithm=None):
        try:
            algo = algorithm or self.hashing_algorithm
            if(os.path.isfile(input_path)):
                hash_val = self.file_handler.calculate_file_hash(input_path, algo)
                if hash_val != "":
                    full_file_info = self.file_handler.extract_file_info(input_path)
                    inode = full_file_info[0]
                    device = full_file_info[1]
                    if self.db_manager.insert_hash(inode, hash_val, device, input_path, algo):
                        self.backup_files.execute_backup_on_created(input_path)
                        return True
                    else:
                        self.log.add_to_log("EXCEPTION", "ERROR", f"STORE HASH fallo | Ruta: {input_path} | Insert en DB fallo")
                        return False
                else:
                    self.log.add_to_log("EXCEPTION", "ERROR", f"STORE HASH fallo | Ruta: {input_path} | Hash vacio")
                    raise Exception
            else:
                hash_array = self.file_handler.calculate_directory_hashes(input_path, algo)
                if (hash_array):
                    for hash_tuple in hash_array:
                        file_path = hash_tuple[0]
                        hash_val = hash_tuple[1]
                        full_file_info = self.file_handler.extract_file_info(file_path)
                        inode = full_file_info[0]
                        device = full_file_info[1]

                        if not self.db_manager.insert_hash(inode, hash_val, device, file_path, algo):
                            self.log.add_to_log("EXCEPTION", "ERROR", f"STORE HASH fallo | Ruta: {file_path} | Insert en DB fallo")
                    return True
                else:
                    print("No hay hash array")
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"STORE HASH fallo | Ruta: {input_path} | Error: {e}")
            return False

    def execute_path_update(self, path):
        try:
            if(os.path.isfile(path)):
                return self.execute_file_update_path(path)
            else:
                return self.execute_directory_update_path(path)
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"PATH UPDATE fallo | Ruta: {path} | Error: {e}")
            return False

    def execute_directory_update_path(self, path):
        try:
            file_paths = []
            for root, dirs, files in os.walk(path):
                data = (root, files)
                for file in data[1]:
                    full_path = data[0] + "/" + file
                    file_paths.append(full_path)
            for file_path in file_paths:
                full_file_info = self.file_handler.extract_file_info(file_path)
                inode = full_file_info[0]
                device = full_file_info[1]
                self.db_manager.update_path(file_path, inode, device)
            return True
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"DIR PATH UPDATE fallo | Ruta: {path} | Error: {e}")
            return False

    def execute_file_update_path(self, path):
        try:
            full_file_info = self.file_handler.extract_file_info(path)
            inode = full_file_info[0]
            device = full_file_info[1]
            self.db_manager.update_path(path, inode, device)
            return True
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"FILE PATH UPDATE fallo | Ruta: {path} | Error: {e}")
            return False

    def consult_hash(self, file_path):
        info = os.stat(file_path)
        inode = info.st_ino
        retrieved_hash = self.db_manager.get_hash_by_inode(inode)
        return retrieved_hash

    def execute_hash_update(self, path):
        try:
            event = None
            successful_update = False
            if(os.path.isfile(path)):
                if(self.execute_file_update_hash(path)):
                     successful_update = True
            else:
                event = self.execute_directory_update_hash(path)
                if(event):
                    successful_update = True
            if(successful_update):
                 print("\n[+] Hash actualizado exitosamente\n")
                 self.log.add_to_log("INTEGRITY", "INFO", f"HASH UPDATED | Ruta: {path}")
                 return event
            else:
                 print("\n[-] Hash fallo en actualizarse\n")
                 self.log.add_to_log("EXCEPTION", "ERROR", f"HASH UPDATE fallo | Ruta: {path}")
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"HASH UPDATE fallo | Ruta: {path} | Error: {e}")
            return False

    def execute_file_update_hash(self, path):
        try:
            hash_val = self.file_handler.calculate_file_hash(path)
            if hash_val != "":
                full_file_info = self.file_handler.extract_file_info(path)
                inode = full_file_info[0]
                device = full_file_info[1]
                self.db_manager.update_hash(hash_val, inode, device)
                return True
            else:
                self.log.add_to_log("EXCEPTION", "ERROR", f"FILE HASH UPDATE fallo | Ruta: {path} | Hash vacio")
                raise Exception
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"FILE HASH UPDATE fallo | Ruta: {path} | Error: {e}")
            return False

    def execute_directory_update_hash(self, path):
        hash_array = self.file_handler.calculate_directory_hashes(path)
        change_id = 0
        all_changes = {}
        if (hash_array):
            for hash_tuple in hash_array:
                change = {}
                change_id += 1
                change["file_path"] = hash_tuple[0]
                change["old_hash"] = self.consult_hash(change["file_path"])
                change["new_hash"] = hash_tuple[1]
                full_file_info = self.file_handler.extract_file_info(hash_tuple[0])
                change["inode"] = full_file_info[0]
                change["device"] = full_file_info[1]
                self.db_manager.update_hash(change["new_hash"], change["inode"], change["device"])
                all_changes[change_id] = change
            return all_changes
        else:
            self.log.add_to_log("EXCEPTION", "ERROR", f"DIR HASH UPDATE fallo | Ruta: {path} | Hash array vacio")
            raise Exception

    def execute_file_update_status(self, inode, status):
        try:
            self.db_manager.update_file_hash_status(inode, status)
            return True
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"UPDATE STATUS fallo | Inode: {inode} | Status: {status} | Error: {e}")
            return False

    def consult_path_hash_existence_in_db(self, path):
        try:
            if(os.path.isfile(path)):
                hash_val = self.file_handler.calculate_file_hash(path)
                if hash_val != "":
                    full_file_info = self.file_handler.extract_file_info(path)
                    inode = full_file_info[0]
                    if(self.db_manager.consult_file_existence(inode)):
                        return True
                    else:
                        return False
                else:
                    self.log.add_to_log("EXCEPTION", "ERROR", f"CONSULT EXISTENCE fallo | Ruta: {path} | Hash vacio")
                    raise Exception
            else:
                hash_array = self.file_handler.calculate_directory_hashes(path)
                results = []
                if (hash_array):
                    for hash_tuple in hash_array:
                        file_path = hash_tuple[0]
                        full_file_info = self.file_handler.extract_file_info(file_path)
                        inode = full_file_info[0]
                        if (self.db_manager.consult_file_existence(inode)):
                            results.append(True)
                    return results
                else:
                    self.log.add_to_log("EXCEPTION", "ERROR", f"CONSULT EXISTENCE DIR fallo | Ruta: {path} | Hash array vacio")
                    return False
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"CONSULT EXISTENCE fallo | Ruta: {path} | Error: {e}")
            return False

    def change_hashing_algorithm(self, eleccion):
        available_algorithms = {
            1: "sha256",
            2: "sha512",
            3: "blake2b",
            4: "sha3_256"
        }
        self.hashing_algorithm = available_algorithms[eleccion]

    def change_algorithm_in_all_db(self):
        self.db_manager.change_hashing_algorithm_DB(self.hashing_algorithm)
