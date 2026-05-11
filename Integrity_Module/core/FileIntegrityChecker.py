import sqlite3
import hashlib  
import os


class FileIntegrityChecker:

    def __init__(self, hash_storage, file_handler, db_manager):
        self.hashing_algorithm = "sha256"
        self.hash_storage = hash_storage
        self.file_handler=file_handler
        self.db_manager=db_manager
    

    def verify_hash_changes_in_directory(self, directory_path):
        all_files = []
        files_hashes = {}
        
        for root, dirs, files in os.walk(directory_path):
            data = (root, files)
            all_files.append(data)
            
        for data_tuple in all_files:
            path = data_tuple[0]
            for file in data_tuple[1]:
                full_path = path + "/" + file
                files_hashes[full_path] = self.file_handler.calculate_file_hash(full_path)
                
        return files_hashes
    

    
    def detect_file_hash_changes(self, path):
        file_info = self.file_handler.extract_file_info(path)
        inode = file_info[0]
        local_db_hash = self.db_manager.get_hash_by_inode(inode)  # db_manager no está en __init__
        new_hash = self.file_handler.calculate_file_hash(path)
        
        if local_db_hash == new_hash:
            print("\n[+] Hashes son iguales.\n")
            return "VERIFIED"
        else:
            print("\n[+] ATENCION!! CAMBIO EN HASHES DETECTADO!!\n")
            return "MODIFIED"
    
    def detect_directory_hash_changes(self, path):
        all_changes = {}
        change_id = 0
        file_hashes = self.verify_hash_changes_in_directory(path)
        
        for file_path, hash_value in file_hashes.items():  
            change_id += 1
            change = {}  
            file_info = self.file_handler.extract_file_info(file_path)
            inode = file_info[0]
            change["inode"] = inode
            change["device"] = file_info[1]
            change["old_hash"] = self.db_manager.get_hash_by_inode(inode) 
            change["new_hash"] = hash_value
            change["file_path"] = file_path
            
            if change["old_hash"] != "":
                if change["old_hash"] == change["new_hash"]:
                    print(f"\n[+] Hashes son iguales para el archivo {file_path}.\n")
                    change["event_type"] = "VERIFIED"
                elif change["old_hash"] != change["new_hash"]:
                    print(f"\n[+] ATENCION!! CAMBIO EN HASHES DETECTADO EN EL ARCHIVO {file_path}!!\n")
                    change["event_type"] = "MODIFIED"
                else:
                    change["event_type"] = "N/A"
            
            all_changes[change_id] = change  
        
        return all_changes  
    
    def detect_any_hash_change(self, path):
        
        if(os.path.isfile(path)):
            flag=self.detect_file_hash_changes(path)
            return flag
        else:
            directory_changes=self.detect_directory_hash_changes(path)
            return directory_changes
        

    


        

    

    
    