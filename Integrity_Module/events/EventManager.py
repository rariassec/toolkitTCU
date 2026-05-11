import hashlib
import os
import sqlite3
import json
from datetime import datetime

class EventManager:
    
    def __init__(self, db_manager, hash_storage, file_handler):
        self.hashing_algorithm="sha256"
        self.db_manager=db_manager
        self.hash_storage=hash_storage
        self.file_handler=file_handler

    def generate_creation_event(self, path):
            event_logged=False
            if(os.path.isfile(path)):
                if(self.file_creation_event(path)):
                    event_logged=True
            else:
                self.directory_creation_event(path)
                if(self.db_manager.consult_new_events_existence()):
                    event_logged=True
            if(event_logged):
                    print("[+] Evento guardado con exito")
            else:
                    print("[-] Evento fallo en guardarse")
            
    def directory_creation_event(self, directory_path):
         all_hashes=self.hash_storage.calculate_directory_hashes(directory_path)
         for file in all_hashes:
              path=file[0]
              hash=file[1]
              file_info= self.file_handler.extract_file_info(path)
              inode=file_info[0]
              device=file_info[1]
              self.db_manager.insert_creation_event(inode, device,hash,path)
              
         

    def file_creation_event(self, file_path):            
            hash=self.file_handler.calculate_file_hash(file_path)
            file_info= self.file_handler.extract_file_info(file_path)
            inode=file_info[0]
            device=file_info[1]
            self.db_manager.insert_creation_event(inode, device,hash,file_path)
            return True
    def generate_modification_event(self, path, event):
           # try:
                event_logged=False
                if(os.path.isfile(path)):
                    if(self.file_modification_event(path, event)):
                         event_logged=True
                else:
                    self.directory_modification_event(event)
                    if(self.db_manager.consult_new_events_existence()):
                        event_logged=True
                if(event_logged):
                     print("[+] Evento guardado con exito")
                else:
                     print("[-] Evento fallo en guardarse")
           # except Exception as e:
            #    print(f"Surgió un error en la creación del evento {e}")
             #   return False

    def file_modification_event(self, path, event_type):
        try:
            file_info=self.file_handler.extract_file_info(path)
            inode=file_info[0]
            device=file_info[1]
            old_hash=self.hash_storage.consult_hash(path)
            new_hash=self.file_handler.calculate_file_hash(path)
            self.db_manager.insert_modification_event(inode, device, old_hash, new_hash, path, event_type)
            return True
        except Exception as e:
            print(f"Surgió un error en la creación del evento {e}")
            return False
            
    def directory_modification_event(self, all_changes):
        # try:
            for dict in all_changes.values():
                if dict["old_hash"] != "" and dict["event_type"] !="":
                    inode=dict["inode"]
                    device=dict["device"]
                    old_hash=dict["old_hash"]
                    new_hash=dict["new_hash"]
                    event_type=dict["event_type"]
                    file_path=dict["file_path"]
                    self.db_manager.insert_modification_event(inode, device, old_hash, new_hash, file_path, event_type)
                else:
                     continue
                
        # except Exception as e:
         #       print(f"Surgió un error en la creación del evento {e}")
         #       return False     
         

    def generate_updated_event(self, path, event):
           # try:
                event_logged=False
                if(os.path.isfile(path) and event==None):
                    if(self.file_updated_event(path)):
                         event_logged=True
                else:
                    self.directory_updated_event(event)
                    if(self.db_manager.consult_new_events_existence()):
                        event_logged=True
                if(event_logged):
                     print("[+] Evento guardado con exito")
                else:
                     print("[-] Evento fallo en guardarse")
           # except Exception as e:
            #    print(f"Surgió un error en la creación del evento {e}")
             #   return False   
    
    def directory_updated_event(self, all_changes):
            
            for dict in all_changes.values():
                if dict["old_hash"] != "":
                    inode=dict["inode"]
                    device=dict["device"]
                    old_hash=dict["old_hash"]
                    new_hash=dict["new_hash"]
                    file_path=dict["file_path"]
                    self.db_manager.insert_updated_event(inode, device, old_hash, new_hash, file_path)
                else:
                     continue
            
    def file_updated_event(self, path):
            try:
                old_hash=self.hash_storage.consult_hash(path)
                new_hash=self.file_handler.calculate_file_hash(path)
                file_info= self.file_handler.extract_file_info(path)
                inode=file_info[0]
                device=file_info[1]
                if(self.db_manager.insert_updated_event(inode, device, old_hash, new_hash, path)):
                    return True
                else:
                    return False
            except Exception as e:
                print(f"Surgió un error en la creación del evento {e}")
                return False

    
            
    

   

