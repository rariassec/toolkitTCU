import sqlite3
import os
from datetime import datetime
import traceback
from toolkitTCU.integrity_module.utils.LoadConfig import ConfigLoader, MODULE_DIR

DB_PATH = os.environ.get("FIM_DB_PATH", os.path.join(MODULE_DIR, "hashes.db"))

class DatabaseManager:
    def __init__(self, load_config:ConfigLoader):
        from toolkitTCU.integrity_module.utils.FileHandler import FileHandler
        from toolkitTCU.integrity_module.utils.Logger import Logger
        self.load_config=load_config
        self.loaded_config=self.load_config.load_config()
        self.log=Logger(self.load_config)
        self.file_handler= FileHandler(self, self.log)
        self.default_algorithms={
            "sha256" : 1,
            "sha512" : 2,
            "blake2b" : 3,
            "sha3_256" : 4
        }
        default_algo_name = self.loaded_config.get("default_hashing_algorithm", "sha256")
        self.hashing_algorithm = self.default_algorithms.get(default_algo_name, 1)
        self.last_scan_session_id= None
        self.last_modified_event_id=None

    def set_DB(self):
        self.create_file_hashes_table()
        self.create_integrity_events_table()
        self.create_backup_table()
        self.create_hash_algorithms_table()
        self.create_scan_sessions_table()
        self.create_session_events_table()
        self.insert_default_algorithms()
        self.log.add_to_log("DATABASE", "INFO", "DB INICIALIZADA | Todas las tablas creadas y algoritmos insertados")

    def create_file_hashes_table(self):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS file_hashes
                    (inode INTEGER, hash TEXT, file_path TEXT, device INTEGER, algorithm_id INTEGER, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, has_backup INTEGER DEFAULT 0, status TEXT, PRIMARY KEY(inode, device), FOREIGN KEY (algorithm_id) REFERENCES hash_algorithms (algorithm_id))''')
        conn.commit()
        conn.close()

    def create_hash_algorithms_table(self):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS hash_algorithms
                    (algorithm_id INTEGER, algorithm_name TEXT, bit_length INTEGER, is_active INTEGER, PRIMARY KEY(algorithm_id))''')
        conn.commit()
        conn.close()

    def insert_default_algorithms(self):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        algoritmos = [
            ('sha256', 256),
            ('sha512', 512),
            ('blake2b', 512),
            ('sha3_256', 256)
        ]

        for name, bits in algoritmos:
            c.execute("""INSERT OR IGNORE INTO hash_algorithms
                        (algorithm_name, bit_length, is_active)
                        VALUES (?, ?, 1)""", (name, bits))

        conn.commit()
        conn.close()

    def create_integrity_events_table(self):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS integrity_events
                    (event_id INTEGER, inode INTEGER, device INTEGER, old_hash TEXT, new_hash TEXT, file_path TEXT, event_type TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, has_backup INTEGER DEFAULT 0, severity TEXT, PRIMARY KEY(event_id))''')
        conn.commit()
        conn.close()

    def create_session_events_table(self):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS session_events
                    (session_id INTEGER, event_id INTEGER, FOREIGN KEY (session_id) REFERENCES scan_sessions (session_id), FOREIGN KEY (event_id) REFERENCES integrity_events (event_id))''')
        conn.commit()
        conn.close()

    def create_scan_sessions_table(self):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS scan_sessions
                    (session_id INTEGER, scan_type TEXT, started_at DATETIME, ended_at DATETIME, files_checked INTEGER, files_changed INTEGER, status TEXT, PRIMARY KEY(session_id))''')
        conn.commit()
        conn.close()

    def create_backup_table(self):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS backup_files
                    (backup_id INTEGER, original_inode INTEGER, original_device INTEGER, backup_inode INTEGER, backup_device INTEGER, backup_path TEXT, hash TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(backup_id), FOREIGN KEY(original_inode) REFERENCES file_hashes(inode), FOREIGN KEY(original_device) REFERENCES file_hashes(device))''')
        conn.commit()
        conn.close()

    def consult_all_registered_files_info(self, path):
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            query="SELECT file_path, algorithm_id FROM file_hashes WHERE file_path = ?"
            c.execute(query, (path,))
            row= c.fetchone()
            conn.close()
            if row is None:
                return None

            algo_map = {1: "SHA-256", 2: "SHA-512", 3: "BLAKE2b", 4: "SHA3-256"}

            algo_name = algo_map.get(row[1], "SHA-256")
            size_str = "N/A"
            if os.path.exists(row[0]):
                try:
                    size_bytes = os.path.getsize(row[0])
                    if size_bytes < 1024:
                        size_str = f"{size_bytes} B"
                    elif size_bytes < 1024 * 1024:
                        size_str = f"{size_bytes / 1024:.1f} KB"
                    else:
                        size_str = f"{size_bytes / (1024 * 1024):.1f} MB"
                except Exception:
                    pass
            file_info={
                "path": row[0],
                "algorithm": algo_name,
                "size": size_str
            }

            return file_info
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"CONSULTAR INFORMACION ARCHIVOS fallo | Error: {e}")
            return []

    def consult_path_of_file(self, file_path):
        try:
            info_file = self.file_handler.extract_file_info(file_path)
            inode = info_file[0]
            conn = sqlite3.connect(DB_PATH)
            res = conn.cursor()
            consulta = "SELECT file_path from file_hashes WHERE inode = ?"
            res.execute(consulta, (inode,))
            row = res.fetchone()
            conn.close()
            if row is None:
                return None
            db_path_file = row[0]
            return db_path_file
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"CONSULTA PATH fallo | Ruta: {file_path} | Error: {e}")
            return None

    def insert_hash(self,inode, hash_value, device, file_path, algorithm=None):
        conn = None
        try:
            if algorithm != None and algorithm not in self.default_algorithms:
                raise Exception("Algoritmo no soportado")
            algo = self.default_algorithms[algorithm] if algorithm in self.default_algorithms else self.hashing_algorithm
            conn = sqlite3.connect(DB_PATH, timeout=10)
            c = conn.cursor()
            query="INSERT OR IGNORE INTO file_hashes (inode, hash, device, file_path, algorithm_id, has_backup, status) VALUES (?, ?, ?, ?, ?, ?, ?)"
            c.execute(query, (inode,hash_value,device,file_path,algo,0,"active"))
            conn.commit()
            return True
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"INSERT HASH fallo | Inode: {inode} | Ruta: {file_path} | Error: {e}")
            return False
        finally:
            if conn is not None:
                conn.close()

    def consult_file_algorithm(self, inode):
        try:
            conn=sqlite3.connect(DB_PATH)
            c = conn.cursor()
            query="SELECT algorithm_name FROM file_hashes LEFT JOIN hash_algorithms ON file_hashes.algorithm_id=hash_algorithms.algorithm_id WHERE inode = ?;"
            c.execute(query, (inode,))
            row=c.fetchone()
            return row[0] if row else "sha256"
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"CONSULTA ALGORITMO fallo | Inode: {inode} | Error: {e}")
            return False

    def update_hash_has_backup(self, inode, device):
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            query="UPDATE file_hashes SET has_backup = 1 WHERE inode = ? AND device = ?"
            c.execute(query, (inode, device))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"UPDATE BACKUP STATUS fallo | Inode: {inode} | Error: {e}")
            return False

    def get_hash_by_inode(self, inode):
        try:
            conn = sqlite3.connect(DB_PATH)
            res = conn.cursor()
            consulta="SELECT * from file_hashes WHERE inode = ?"
            res.execute(consulta, (inode,))
            row=res.fetchone()
            if row:
                return row[1]
            else:
                return ""
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"GET HASH fallo | Inode: {inode} | Error: {e}")
            return ""

    def update_path(self, dest, inode, device):
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            consulta="UPDATE file_hashes SET file_path = ? WHERE inode = ? AND device = ?"
            c.execute(consulta, (dest, inode, device))
            conn.commit()
            conn.close()
            return c.rowcount > 0
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"UPDATE PATH fallo | Dest: {dest} | Inode: {inode} | Error: {e}")
            return False

    def update_hash(self, hash, inode, device):
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            consulta="UPDATE file_hashes SET hash = ? WHERE inode = ? AND device = ?"
            c.execute(consulta, (hash, inode, device))
            conn.commit()
            conn.close()
            return c.rowcount > 0
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"UPDATE HASH fallo | Inode: {inode} | Error: {e}")
            return False

    def update_file_record_by_path(self, file_path, inode, device, new_hash, status="modified"):
        conn = None
        try:
            conn = sqlite3.connect(DB_PATH, timeout=10)
            c = conn.cursor()
            consulta = "UPDATE file_hashes SET inode = ?, device = ?, hash = ?, status = ? WHERE file_path = ?"
            c.execute(consulta, (inode, device, new_hash, status, file_path))
            conn.commit()
            return c.rowcount > 0
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"UPDATE FILE RECORD fallo | Ruta: {file_path} | Error: {e}")
            return False
        finally:
            if conn is not None:
                conn.close()

    def update_file_identity_by_path(self, file_path, inode, device, status="modified"):
        conn = None
        try:
            conn = sqlite3.connect(DB_PATH, timeout=10)
            c = conn.cursor()
            consulta = "UPDATE file_hashes SET inode = ?, device = ?, status = ? WHERE file_path = ?"
            c.execute(consulta, (inode, device, status, file_path))
            conn.commit()
            return c.rowcount > 0
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"UPDATE FILE IDENTITY fallo | Ruta: {file_path} | Error: {e}")
            return False
        finally:
            if conn is not None:
                conn.close()

    def update_file_path_by_path(self, old_path, new_path, inode, device):
        conn = None
        try:
            conn = sqlite3.connect(DB_PATH, timeout=10)
            c = conn.cursor()
            consulta = "UPDATE file_hashes SET file_path = ?, inode = ?, device = ? WHERE file_path = ?"
            c.execute(consulta, (new_path, inode, device, old_path))
            conn.commit()
            return c.rowcount > 0
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"RENAME FILE RECORD fallo | {old_path} -> {new_path} | Error: {e}")
            return False
        finally:
            if conn is not None:
                conn.close()

    def consult_file_existence(self, inode):
        try:
            conn = sqlite3.connect(DB_PATH)
            res = conn.cursor()
            consulta="SELECT * from file_hashes WHERE inode = ?"
            res.execute(consulta, (inode,))
            if(res.fetchone()):
                return True
            else:
                return False
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"CONSULTA EXISTENCIA ARCHIVO fallo | Inode: {inode} | Error: {e}")
            return False

    def change_hashing_algorithm_DB(self, hashing_algorithm):
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("SELECT inode, file_path, device FROM file_hashes")
            rows=c.fetchall()
            for inode, file_path, device in rows:
                if not os.path.exists(file_path):
                        self.log.add_to_log("EXCEPTION", "WARNING", f"CAMBIO ALGORITMO omitido | Ruta: {file_path} | No existe")
                        continue
                with open(file_path, "rb") as f:
                    new_hash=self.file_handler.calculate_file_hash(file_path)
                    consulta=("UPDATE file_hashes SET hash= ? WHERE inode = ? AND device = ?")
                    c.execute(consulta, (new_hash, inode, device))
                    conn.commit()
                    f.close()
            conn.close()
            self.log.add_to_log("DATABASE", "INFO", f"CAMBIO ALGORITMO | Algoritmo: {hashing_algorithm} | Archivos actualizados: {len(rows)}")
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"CAMBIO ALGORITMO fallo | Error: {e}")

    def update_file_hash_status(self, inode, status):
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            consulta="UPDATE file_hashes SET status = ? WHERE inode = ?"
            c.execute(consulta, (status, inode))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            self.log.add_to_log("EXCEPTION", "ERROR", f"UPDATE STATUS fallo | Inode: {inode} | Status: {status} | Error: {e}")
            return False
    def obtain_full_info_by_path(self, path):
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            consulta="SELECT * from file_hashes WHERE file_path = ?"
            c.execute(consulta, (path,))
            row=c.fetchone()
            if row:
                columns = [description[0] for description in c.description]
                full_info=dict(zip(columns, row))
                conn.close()
                return full_info
            else:
                conn.close()
                return None
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"OBTENER INFO fallo | Ruta: {path} | Error: {e}")
            return None

    def insert_backup_event(self,inode, device, old_hash, new_hash, file_path):
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            consulta='INSERT INTO integrity_events (inode, device, old_hash, new_hash, file_path, event_type) VALUES (?,?,?,?,?,?)'
            c.execute(consulta, (inode,device,old_hash, new_hash,file_path, "BACKUP"))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"INSERT BACKUP EVENT fallo | Ruta: {file_path} | Error: {e}")
            return False

    def insert_creation_event(self, inode,device,hash,file_path, severity):
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            consulta='INSERT INTO integrity_events (inode, device, old_hash, new_hash, file_path, event_type, severity) VALUES (?,?,?,?,?,?,?)'
            c.execute(consulta, (inode,device,hash, hash,file_path, "CREATED", severity))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"INSERT CREATED EVENT fallo | Ruta: {file_path} | Error: {e}")
            return False

    def insert_modification_event(self, inode, device, old_hash, new_hash, file_path, event_type, severity):
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            consulta='INSERT INTO integrity_events (inode, device, old_hash, new_hash, file_path, event_type, severity) VALUES (?,?,?,?,?,?,?)'
            c.execute(consulta, (inode,device,old_hash, new_hash,file_path, event_type, severity))
            conn.commit()
            conn.close()
            self.last_modified_event_id=c.lastrowid
            return True
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"INSERT {event_type} EVENT fallo | Ruta: {file_path} | Error: {e}")
            return False

    def insert_updated_event(self,inode, device, old_hash, new_hash, file_path):
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            consulta='INSERT INTO integrity_events (inode, device, old_hash, new_hash, file_path, event_type) VALUES (?,?,?,?,?,?)'
            c.execute(consulta, (inode,device,old_hash, new_hash,file_path, "UPDATED"))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"INSERT UPDATED EVENT fallo | Ruta: {file_path} | Error: {e}")
            return False

    def insert_deleted_event(self, path, inode, device, old_hash, severity):
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            consulta='INSERT INTO integrity_events (inode, device, old_hash, new_hash, file_path, event_type, severity) VALUES (?,?,?,?,?,?,?)'
            c.execute(consulta, (inode,device,old_hash, old_hash, path, "DELETED", severity))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"INSERT DELETED EVENT fallo | Ruta: {path} | Error: {e}")
            return False

    def insert_backup_file(self, original_inode, original_device, backup_inode, backup_device, backup_path, hash):
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            consulta='INSERT INTO backup_files (original_inode, original_device, backup_inode, backup_device, backup_path, hash) VALUES (?,?,?,?,?,?)'
            c.execute(consulta, (original_inode, original_device, backup_inode, backup_device, backup_path, hash))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"INSERT BACKUP FILE fallo | Backup: {backup_path} | Error: {e}")
            return False

    def consult_reports_existence(self):
        try:
            consulta="SELECT * FROM integrity_events"
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute(consulta)
            data=c.fetchall()
            return bool(data)
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"CONSULTA EXISTENCIA REPORTES fallo | Error: {e}")
            return False

    def consult_new_events_existence(self):
        try:
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            consulta="SELECT * FROM integrity_events WHERE timestamp >= ?"
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute(consulta, (now,))
            data=c.fetchall()
            return bool(data)
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"CONSULTA NUEVOS EVENTOS fallo | Error: {e}")
            return False

    def consult_inode_and_device_by_path(self, path):
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            query="SELECT inode, device FROM file_hashes WHERE file_path = ?"
            c.execute(query, (path,))
            data=c.fetchone()
            if data:
                return data[0], data[1]
            else:
                return None
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"CONSULTA INODE/DEVICE fallo | Ruta: {path} | Error: {e}")
            return None

    def obtain_info_for_general_report(self):
        try:
            conn = sqlite3.connect(DB_PATH)
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
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"OBTENER REPORTE GENERAL fallo | Error: {e}")
            return []

    def get_events_with_severity(self):
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute(
                "SELECT event_id, event_type, file_path, severity, timestamp "
                "FROM integrity_events ORDER BY timestamp DESC"
            )
            events = []
            for row in c.fetchall():
                events.append({
                    "event_id": row[0],
                    "event_type": row[1],
                    "file_path": row[2],
                    "severity": row[3],
                    "timestamp": row[4],
                })
            conn.close()
            return events
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"OBTENER EVENTOS CON SEVERIDAD fallo | Error: {e}")
            return []

    def obtain_info_for_individual_report(self):
        try:
            conn = sqlite3.connect(DB_PATH)
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
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"OBTENER REPORTES INDIVIDUALES fallo | Error: {e}")
            return []

    def update_backup_status(self, event_id):
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            consulta="UPDATE integrity_events SET has_backup = 1 WHERE event_id = ?"
            c.execute(consulta, (event_id,))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"UPDATE BACKUP STATUS EVENT fallo | Event ID: {event_id} | Error: {e}")
            return False

    def consult_all_file_paths(self):
        try:
            all_paths=[]
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            query="SELECT file_path FROM file_hashes"
            c.execute(query)
            for path in c.fetchall():
                all_paths.append(path[0])
            conn.close()
            return all_paths
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"CONSULTAR TODOS LOS PATHS fallo | Error: {e}")
            return []

    def consult_all_deleted_files(self):
        try:
            all_deleted_files=[]
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            query="SELECT * FROM file_hashes WHERE status = ?"
            c.execute(query, ("deleted",))
            columns = [description[0] for description in c.description]
            for deleted_file in c.fetchall():
                deleted_file=dict(zip(columns, deleted_file))
                all_deleted_files.append(deleted_file)
            conn.close()
            return all_deleted_files
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"CONSULTAR TODOS LOS PATHS fallo | Error: {e}")
            return []

    def consulta_all_file_inodes(self):
        try:
            all_inodes=[]
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            query="SELECT inode FROM file_hashes"
            c.execute(query)
            for inode in c.fetchall():
                all_inodes.append(inode[0])
            conn.close()
            return all_inodes
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"CONSULTAR TODOS LOS INODES fallo | Error: {e}")
            return []

    def consult_all_info_backup_file(self, original_inode, original_device):
        try:

            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            query="SELECT * FROM backup_files WHERE original_inode=? AND original_device=? ORDER BY timestamp DESC LIMIT 1"
            c.execute(query, (original_inode, original_device))
            row=c.fetchone()
            columns = [description[0] for description in c.description]
            conn.close()
            if row is None:
                return None
            backup_file=dict(zip(columns, row))
            return backup_file
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"CONSULTAR EL BACKUP_PATH fallo | Error: {e}")
            return ""

    def consult_all_info_backup_file_by_path(self, path):
        try:

            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            query="SELECT * FROM backup_files WHERE backup_path=? ORDER BY timestamp DESC LIMIT 1"
            c.execute(query, (path,))
            row=c.fetchone()
            columns = [description[0] for description in c.description]
            conn.close()
            if row is None:
                return None
            backup_file=dict(zip(columns, row))
            return backup_file
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"CONSULTAR EL BACKUP_PATH fallo | Error: {e}")
            return ""

    def consult_file_status(self, inode):
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            query="SELECT status FROM file_hashes WHERE inode=?"
            c.execute(query, (inode,))
            row = c.fetchone()
            conn.close()
            return row[0] if row else None
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"CONSULTAR TODOS LOS CAMBIOS fallo | Error: {e}")
            return []
    def consult_all_changes(self):
        try:
            all_changes=[]
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            query="SELECT * FROM file_hashes WHERE status=? OR status=?"
            c.execute(query, ("modified", "deleted"))
            columns = [description[0] for description in c.description]
            for row in c.fetchall():
                changed_file=dict(zip(columns, row))
                all_changes.append(changed_file)
            conn.close()
            return all_changes
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"CONSULTAR TODOS LOS CAMBIOS fallo | Error: {e}")
            return []

    def update_file_info_according_backup(self, original_inode, backup_inode, backup_hash):
        try:
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            consulta="UPDATE file_hashes SET inode = ?, hash=?, timestamp=?, has_backup=?, status=? WHERE inode = ?"
            c.execute(consulta, (backup_inode, backup_hash, now, 0, "verified", original_inode))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"LA ACTUALIZACION SEGUN BACKUP fallo | Error: {e}")
            return False

    def insert_scan_session(self, scan_type, started_at, ended_at, files_checked, files_changed, status):
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            consulta='INSERT INTO scan_sessions (scan_type, started_at, ended_at, files_checked, files_changed, status) VALUES (?,?,?,?,?,?)'
            c.execute(consulta, (scan_type,started_at, ended_at, files_checked, files_changed, status))
            conn.commit()
            conn.close()
            self.last_scan_session_id=c.lastrowid
            return True
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"INSERT SCAN SESSION FALLO | Timestamp: {ended_at} Error: {e}")
            return False

    def get_last_scan_session_id(self):
        return self.last_scan_session_id

    def insert_session_events(self, scan_session_id, event_id):
        try:
            if scan_session_id==None:
                return
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            consulta='INSERT INTO session_events (session_id, event_id) VALUES (?,?)'
            c.execute(consulta, (scan_session_id, event_id))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error: {e}")
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"INSERT SESSION EVENTS FALLO | Error: {e}")
            return False
    def get_last_modified_event_id(self):
        return self.last_modified_event_id

    def consult_all_file_info_by_path(self, file_path):
        try:
            full_info={}
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            query="SELECT * FROM file_hashes WHERE file_path=?"
            c.execute(query, (file_path,))
            columns = [description[0] for description in c.description]
            for row in c.fetchall():
                full_info=dict(zip(columns, row))
            conn.close()
            return full_info
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"CONSULTAR TODOS LOS CAMBIOS fallo | Error: {e}")
            return {}

    def consult_file_existence_by_path(self, file_path):
        try:
            conn = sqlite3.connect(DB_PATH)
            res = conn.cursor()
            consulta="SELECT * from file_hashes WHERE file_path = ?"
            res.execute(consulta, (file_path,))
            if(res.fetchone()):
                return True
            else:
                return False
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"CONSULTA EXISTENCIA ARCHIVO fallo | File_path: {file_path} | Error: {e}")
            return False

    def get_total_files_monitored(self):
        try:
            conn = sqlite3.connect(DB_PATH)
            res = conn.cursor()
            consulta="SELECT COUNT(*) FROM file_hashes"
            res.execute(consulta)
            files_monitored=res.fetchone()[0]
            return files_monitored
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"CONSULTA ARCHIVOS MONITOREADOS FALLO")
            return False

    def get_last_scan_session(self):
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            res = conn.cursor()
            consulta="SELECT ended_at FROM scan_sessions ORDER BY session_id DESC LIMIT 1"
            res.execute(consulta)
            last_session = res.fetchone()
            last_scan_date = "N/A"
            last_scan_time = "N/A"
            if last_session:
                dt_end = datetime.strptime(last_session['ended_at'], '%Y-%m-%d %H:%M:%S')
                last_scan_date = dt_end.strftime('%d/%m/%Y')
                last_scan_time = dt_end.strftime('%H:%M:%S')
            conn.close()
            return last_scan_date, last_scan_time
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"CONSULTA ULTIMA SESION ESCANEO FALLO | Error: {e}")
            return "N/A", "N/A"

    def get_detected_changes(self):
        try:
            conn = sqlite3.connect(DB_PATH)
            res = conn.cursor()
            consulta="SELECT COUNT(*) FROM file_hashes WHERE status = 'modified' OR status = 'deleted'"
            res.execute(consulta)
            changes_detected=res.fetchone()[0]
            return changes_detected
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"CONSULTA ARCHIVOS MONITOREADOS FALLO")
            return False

    def get_avg_scan_time(self):
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            res = conn.cursor()
            consulta="SELECT started_at, ended_at FROM scan_sessions WHERE started_at IS NOT NULL AND ended_at IS NOT NULL"
            res.execute(consulta)
            durations=[]
            sessions= res.fetchall()
            for s in sessions:
                t_start= datetime.strptime(s['started_at'], '%Y-%m-%d %H:%M:%S')
                t_end = datetime.strptime(s['ended_at'], '%Y-%m-%d %H:%M:%S')
                durations.append((t_end - t_start).total_seconds())
            conn.close()
            avg_dur= sum(durations) / len(durations) if durations else 0.0
            return avg_dur
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"CONSULTA TIEMPO PROMEDIO ESCANEO FALLO | Error: {e}")
            return 0.0

    def get_changes_last_7_days(self):
        try:
            full_info={}
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("""
                SELECT strftime('%d/%m', timestamp) as day, COUNT(*) as cnt
                FROM integrity_events
                WHERE event_type IN ('CREATED', 'MODIFIED', 'DELETED') AND date(timestamp) >= date('now', '-6 days')
                GROUP BY day
            """)
            events_7_map = {r['day']: r['cnt'] for r in c.fetchall() if r['day']}
            return events_7_map
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"CONSULTAR TODOS LOS CAMBIOS fallo | Error: {e}")
            return {}

    def get_all_files_from_changes(self):
        try:
            full_info={}
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("""
                SELECT file_path FROM integrity_events
            """)
            results=c.fetchall()
            files= [r[0] for r in results]
            return files
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"CONSULTAR TODOS LOS CAMBIOS fallo | Error: {e}")
            return []

    def get_all_events_per_day(self):
        try:
            """
            eventos_por_dia =
                {
                '2024-01-01': 5
                },
                ...
            """
            full_info={}
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("""
                SELECT strftime('%Y-%m-%d', timestamp) as date, COUNT(*) as total FROM integrity_events GROUP BY date ORDER BY total
            """)
            events_30_map = {r['date']: r['total'] for r in c.fetchall() if r['date']}
            return events_30_map
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"CONSULTAR TODOS LOS CAMBIOS fallo | Error: {e}")
            return {}

    def get_detected_events(self):
        try:
            recent_events = []
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT file_path, event_type, timestamp, new_hash FROM integrity_events ORDER BY timestamp DESC LIMIT 10")
            events_rows = c.fetchall()
            for r in events_rows:
                recent_events.append({
                    "path": r['file_path'],
                    "event_type": r['event_type'],
                    "time": r['timestamp'],
                    "hash_short": r['new_hash'][:8] + "..." if r['new_hash'] else "N/A"
                })
            conn.close()
            return recent_events
        except Exception as e:
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"CONSULTAR ULTIMOS EVENTOS DETECTADOS FALLO | Error: {e}")
            return []

