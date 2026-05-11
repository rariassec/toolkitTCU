import sqlite3
import hashlib  
import os
import json
from datetime import datetime

class HashStorage:

    """CLASE PARA MANEJAR EL ALMACENAMIENTO DE HASHES"""
    def __init__(self, db_manager, file_handler):
        self.db_manager = db_manager
        self.file_handler = file_handler
        self.hashing_algorithm = "sha256"


    def calculate_file_hash(self,file_path):
        try:
            hash=hashlib.new(self.hashing_algorithm)
            buffer_size=65536 #64 kb
            with open (file_path, "rb") as f:
                while True:
                    data=f.read(buffer_size)
                    if not data:
                        break
                    hash.update(data)
            hash=hash.hexdigest()
            return hash
        except Exception as e:
            print(f"Error al almacenar el hash fdfd: {e}")
            return ""
        
    def store_hash(self, input_path):
        try:
            if(os.path.isfile(input_path)):
                hash=self.calculate_file_hash(input_path)
                if hash!="":
                    full_file_info=self.file_handler.extract_file_info(input_path)
                    inode=full_file_info[0]
                    device=full_file_info[1]
                    if not self.db_manager.insert_hash(inode,hash,device,input_path):
                        print(f"\n[+] ERROR. El insert falló para el archivo {input_path}\n")
                    return True
                else:
                    print("\nEl hash estaba vacio y levante el error 1\n")
                    raise Exception
            else:
                hash_array=self.calculate_directory_hashes(input_path)
                if (hash_array):
                    for hash_tuple in hash_array:
                        file_path=hash_tuple[0]
                        hash=hash_tuple[1]
                        full_file_info=self.file_handler.extract_file_info(file_path)
                        inode=full_file_info[0]
                        device=full_file_info[1]
                        if not self.db_manager.insert_hash(inode,hash,device,file_path):
                            print(f"\n[+] ERROR. El insert falló para el archivo {file_path}\n")
                    return True
                else:
                    raise Exception
        except Exception as e:
            print(f"\n[-] Ocurrió un error al almacenar el hash: {e}\n")
            return False
        
    def consult_hash(self, file_path):
        info=os.stat(file_path)
        inode=info.st_ino
        retrieved_hash=self.db_manager.get_hash_by_inode(inode)
        return retrieved_hash

    def calculate_directory_hashes(self, file_path):
        all_files=[]
        new_all_files=[]
        all_hashes=[]
        for root, dirs, files in os.walk(file_path):
            data=(root,files)
            all_files.append(data)

        for data_tuple in all_files:
            path=data_tuple[0]
            for file in data_tuple[1]:
                full_path=path+"/"+file
                new_all_files.append(full_path)
        
        for path_item in new_all_files:
            hash=self.calculate_file_hash(path_item)
            full_data_hash=(path_item,hash)
            all_hashes.append(full_data_hash)
        return all_hashes
    
            
    
    def execute_hash_update(self, path):
        # try:
                event=None
                successful_update=False
                if(os.path.isfile(path)):
                    if(self.execute_file_update_hash(path)):
                         successful_update=True
                else:
                    event=self.execute_directory_update_hash(path)
                    if(event):
                        successful_update=True
                        print("Executing directory updates...")
                if(successful_update):
                     print("[+] Evento guardado con exito")
                     return event #Es none cuando es archivo
                else:
                     print("[-] Evento fallo en guardarse")
           # except Exception as e:
            #    print(f"Surgió un error en la creación del evento {e}")
             #   return False   
            



    def execute_file_update_hash(self,path):
        try:
            hash=self.calculate_file_hash(path)
            print(f"\n[+] El hash del archivo es {hash}\n")
            if hash!="":
                full_file_info=self.file_handler.extract_file_info(path)
                inode=full_file_info[0]
                device=full_file_info[1]
                self.db_manager.update_hash(inode,hash,device,path)
                return True
            else:
                print("\nEl hash estaba vacio y levante el error 1\n")
                raise Exception
            
        except Exception as e:
            print(f"Error al almacenar el hash hfjdshj: {e}")
            print()
            return False
        

    def execute_directory_update_hash(self, path):
        hash_array=self.calculate_directory_hashes(path)
        change_id = 0
        all_changes = {}
        if (hash_array):
            for hash_tuple in hash_array:
                change={}
                change_id+=1
                change["file_path"]=hash_tuple[0]
                change["old_hash"] = self.consult_hash(change["file_path"])
                change["new_hash"]=hash_tuple[1]
                full_file_info=self.file_handler.extract_file_info(hash_tuple[0])
                change["inode"]=full_file_info[0]
                change["device"]=full_file_info[1]
                self.db_manager.update_hash(change["new_hash"], change["inode"], change["device"])
                print(f"[+] El nuevo hash para el archivo {change["file_path"]} es {change["new_hash"]}")
                all_changes[change_id]=change
            return all_changes
        else:
            print("\nEl hash estaba vacio y levante el error 2\n")
            raise Exception
        
        
    def consult_path_hash_existence_in_db(self, path):
        if(os.path.isfile(path)):
                hash=self.calculate_file_hash(path)
                if hash!="":
                    full_file_info=self.file_handler.extract_file_info(path)
                    inode=full_file_info[0]
                    if(self.db_manager.consult_file_existence(inode)):
                        return True
                    else:
                        return False
                else:
                    print("\nEl hash estaba vacio y levante el error 1\n")
                    raise Exception
        else:
            hash_array=self.calculate_directory_hashes(path)
            if (hash_array):
                inode=""
                for hash_tuple in hash_array:
                    file_path=hash_tuple[0]
                    full_file_info=self.file_handler.extract_file_info(file_path)
                    inode=full_file_info[0]
                    if not (self.db_manager.consult_file_existence(inode)):
                        print(f"\n[-] No se pudo calcular el hash para el archivo {inode} ya que archivo no existe\n")
                        return False  # Solo falla aquí si encuentra un archivo inexistente
                return True
        
        
    def change_hashing_algorithm(self, eleccion):
        available_algorithms={
            1:"sha256",
            2:"sha512",
            3:"blake2b",
            4:"sha3_256"
        }
        self.hashing_algorithm= available_algorithms[eleccion]

    def change_algorithm_in_all_db(self):
        self.db_manager.change_hashing_algorithm_DB(self.hashing_algorithm)
