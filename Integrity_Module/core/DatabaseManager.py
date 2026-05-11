import sqlite3
import hashlib
import os
from utils.FileHandler import FileHandler
import json
from datetime import datetime

class DatabaseManager:
    def __init__(self):
        self.file_handler=FileHandler(self)

    def set_DB(self):
        self.create_file_hashes_table()
        self.create_reports_table()
        
    def create_file_hashes_table(self):
        conn = sqlite3.connect('hashes.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS file_hashes
                    (inode INTEGER, hash TEXT, file_path TEXT, device TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(inode, device))''')
        conn.commit()
        conn.close()


    def create_reports_table(self):
        conn = sqlite3.connect('hashes.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS integrity_events
                    (event_id INTEGER, inode INTEGER, device TEXT, old_hash TEXT, new_hash TEXT, file_path TEXT, event_type TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(event_id))''')
        #Event_type: CREATED, MODIFIED, VERIFIED, UPDATED
        conn.commit()
        conn.close()

    def consult_path_of_file(self, file_path):
        info_file = self.file_handler.extract_file_info(file_path)
        inode = info_file[0]
        conn = sqlite3.connect(self.hash_storage.db_manager.db_name)
        res = conn.cursor()
        consulta = "SELECT file_path from file_hashes WHERE inode = ?"
        res.execute(consulta, (inode,))
        db_path_file = res.fetchone()[0]
        conn.close()
        print(f"\n[+]El path registrado en la base de datos del archivo es: {db_path_file}\n")
        return db_path_file
    

    def insert_hash(self,inode, hash_value, device, file_path):
        try:
            conn = sqlite3.connect('hashes.db')
            c = conn.cursor() 
            query="INSERT INTO file_hashes (inode, hash, device, file_path) VALUES (?, ?, ?, ?)"
            c.execute(query, (inode,hash_value,device,file_path))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error al almacenar el hash hfjdshj: {e}")
            print()
            return False 
        
    def get_hash_by_inode(self, inode):
        conn = sqlite3.connect('hashes.db')
        res = conn.cursor()  
        consulta="SELECT * from file_hashes WHERE inode = ?"
        res.execute(consulta, (inode,))
        row=res.fetchone()
        if row:
            return row[1]
        else:
            return ""
        
    def update_hash(self, hash, inode, device):
        try:
            conn = sqlite3.connect('hashes.db')
            c = conn.cursor()  
            consulta="UPDATE file_hashes SET hash = ? WHERE inode = ? AND device = ?"
            c.execute(consulta, (hash, inode, device))
            conn.commit()
            conn.close()
            return c.rowcount > 0
        except Exception as e:
            print(f"Error al almacenar el hash: {e}")
            return False  
        
    def consult_file_existence(self, inode):
        conn = sqlite3.connect('hashes.db')
        res = conn.cursor()  
        consulta="SELECT * from file_hashes WHERE inode = ?"
        res.execute(consulta, (inode,))
        if(res.fetchone()):
            return True
        else:        
            return False
    
    def change_hashing_algorithm_DB(self, hashing_algorithm):
    
        conn = sqlite3.connect('hashes.db')
        c = conn.cursor()  
        c.execute("SELECT inode, file_path, device FROM file_hashes")
        rows=c.fetchall()
        for inode, file_path, device in rows:
            
            with open(file_path, "rb") as f:
                if not os.path.exists(file_path):
                    print(f"\n[-] El archivo {file_path} no existe, no se puede actualizar el hash\n")
                    continue
                new_hash=self.file_handler.calculate_file_hash(file_path)
                consulta=("UPDATE file_hashes SET hash= ? WHERE inode = ? AND device = ?")
                c.execute(consulta, (new_hash, inode, device))
                print(f"\n[+] El nuevo hash con el algorithmo {hashing_algorithm} para {file_path} es {new_hash}\n")
                conn.commit()
                f.close()
        conn.close()

        

    def insert_creation_event(self, inode,device,hash,file_path):
        try:
            conn = sqlite3.connect('hashes.db')
            c = conn.cursor()
            consulta='INSERT INTO integrity_events (inode, device, old_hash, new_hash, file_path, event_type) VALUES (?,?,?,?,?,?)'
            c.execute(consulta, (inode,device,hash, hash,file_path, "CREATED"))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Surgió un error en la creación del evento {e}")
            return False
    
    def insert_modification_event(self, inode, device, old_hash, new_hash, file_path, event_type):
        try:
            conn = sqlite3.connect('hashes.db')
            c = conn.cursor()
            consulta='INSERT INTO integrity_events (inode, device, old_hash, new_hash, file_path, event_type) VALUES (?,?,?,?,?,?)'
            c.execute(consulta, (inode,device,old_hash, new_hash,file_path, event_type))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Surgió un error en la creación del evento {e}")
            return False
        
    def insert_updated_event(self,inode, device, old_hash, new_hash, file_path):
        try:
            conn = sqlite3.connect('hashes.db')
            c = conn.cursor()
            consulta='INSERT INTO integrity_events (inode, device, old_hash, new_hash, file_path, event_type) VALUES (?,?,?,?,?,?)'
            c.execute(consulta, (inode,device,old_hash, new_hash,file_path, "UPDATED"))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Surgió un error en la creación del evento {e}")
            return False
        

    def consult_reports_existence(self):
        consulta="SELECT * FROM integrity_events"
        conn = sqlite3.connect('hashes.db')
        c = conn.cursor()  
        c.execute(consulta)
        data=c.fetchall()
        if data:
            print("\n[+] Hay reportes disponibles\n")
            return True
        else:
            print("\n[-] No hay reportes disponibles\n")
            return False
    def consult_new_events_existence(self):
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        consulta="SELECT * FROM integrity_events WHERE timestamp >= ?"
        conn = sqlite3.connect('hashes.db')
        c = conn.cursor()  
        c.execute(consulta, (now,))
        data=c.fetchall()
        if data:
            return True
        else:
            return False
        
    def obtain_info_for_general_json_report(self):
        conn = sqlite3.connect('hashes.db')
        c = conn.cursor()  
        c.execute("SELECT inode, device, old_hash, new_hash, file_path, event_type, timestamp FROM integrity_events")
        data=c.fetchall()
        report={}
        general_report=[]
        for row in data:
            report={
                "Event Type": row[5],
                "Inode": row[0],
                "Device": row[1],
                "old_hash": row[2],
                "new_hash": row[3],
                "file_path": row[4],
                "timestamp": row[-1]
            }
            general_report.append(report)
        return general_report
    
    def obtain_info_for_individual_json_report(self):
        conn = sqlite3.connect('hashes.db')
        c = conn.cursor()  
        c.execute("SELECT inode, device, old_hash, new_hash, file_path, event_type, timestamp FROM integrity_events")
        data=c.fetchall()
        all_reports=[]
        report={}
        for row in data:
            report={
                "Event Type": row[5],
                "Inode": row[0],
                "Device": row[1],
                "old_hash": row[2],
                "new_hash": row[3],
                "file_path": row[4],
                "timestamp": row[-1]
            }
            all_reports.append(report)
        return all_reports




        
        