import os
import hashlib
import traceback
from pathlib import Path

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from toolkitTCU.integrity_module.core import DatabaseManager
    from toolkitTCU.integrity_module.utils import Logger

class FileHandler:

    def __init__(self, db_manager:"DatabaseManager", log:"Logger"):
        self.hashing_algorithm="sha256"
        self.db_manager=db_manager
        self.log=log

    def extract_file_info(self,file_path):
        info=os.stat(file_path)
        device=info.st_dev
        if os.name == 'nt':
            inode = str(Path(file_path).resolve()).lower()
        else:
            inode=info.st_ino
        full_info=(inode,device)
        return full_info

    def calculate_file_hash(self,file_path, algorithm=None):
        try:
            if not os.path.isfile(file_path):
                return ""
            algo = algorithm or self.hashing_algorithm
            hash=hashlib.new(algo)
            buffer_size=65536
            with open (file_path, "rb") as f:
                while True:
                    data=f.read(buffer_size)
                    if not data:
                        break
                    hash.update(data)
            hash=hash.hexdigest()
            return hash
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"CALCULATE HASH fallo | Ruta: {file_path} | Algoritmo: {algorithm or self.hashing_algorithm} | Error: {e}")
            return ""

    def calculate_directory_hashes(self, file_path, algorithm=None):
        try:
            algo=algorithm or self.hashing_algorithm
            all_files=[]
            new_all_files=[]
            all_hashes=[]
            for root, dirs, files in os.walk(file_path):
                data=(root,files)
                all_files.append(data)

            for data_tuple in all_files:
                path=data_tuple[0]
                for file in data_tuple[1]:
                    full_path=os.path.join(path,file)
                    new_all_files.append(full_path)

            for path_item in new_all_files:
                if not os.path.isfile(path_item):
                    continue
                hash=""
                inode=self.extract_file_info(path_item)[0]
                if not self.db_manager.consult_file_existence(inode):
                    file_algo=algo
                else:
                    file_algo=self.db_manager.consult_file_algorithm(inode)
                hash=self.calculate_file_hash(path_item, file_algo)
                full_data_hash=(path_item,hash)
                all_hashes.append(full_data_hash)

            return all_hashes
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"CALCULATE DIR HASHES fallo | Ruta: {file_path} | Error: {e}")
            return []

    def calculate_file_size(self,file_path):
        try:
            size=os.path.getsize(file_path)
            if size < 1024:
                return f"{size} B"
            elif size < 1024*1024:
                return f"{size/1024:.2f} KB"
            elif size < 1024*1024*1024:
                return f"{size/(1024*1024):.2f} MB"
            else:
                return f"{size/(1024*1024*1024):.2f} GB"
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"CALCULATE FILE SIZE fallo | Ruta: {file_path} | Error: {e}")
            return "0 B"
