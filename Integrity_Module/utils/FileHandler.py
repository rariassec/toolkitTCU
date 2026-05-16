
import os
import hashlib
import sqlite3

class FileHandler:
    
    def __init__(self, db_manager):
        self.hashing_algorithm="sha256"
        self.db_manager=db_manager


    def extract_file_info(self,file_path):
        info=os.stat(file_path)
        inode=info.st_ino
        device=info.st_dev
        full_info=(inode,device)
        return full_info


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
        print(all_hashes)
        # print(f"\nEl hash calculado para el arhivo {path_item} es {hash}\n")
        return all_hashes

            
                        
        #except Exception as e:
         #   print(f"Error al detectar cambios en hash: {e}")
        #   return False
        