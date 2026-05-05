import sqlite3
import hashlib  
import os
import json
from datetime import datetime

hashing_algorithm ="sha256"

def set_DB():
    create_file_hashes_table()
    create_reports_table()
    
def create_file_hashes_table():
    conn = sqlite3.connect('hashes.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS file_hashes
                 (hash_id INTEGER, inode INTEGER, hash TEXT, file_path TEXT, device TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(hash_id,inode, device))''')
    conn.commit()
    conn.close()


def create_reports_table():
    conn = sqlite3.connect('hashes.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS integrity_events
                 (event_id INTEGER, inode INTEGER, device TEXT, old_hash TEXT, new_hash TEXT, file_path TEXT, event_type TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(event_id))''')
    #Event_type: CREATED, MODIFIED, VERIFIED, UPDATED
    conn.commit()
    conn.close()

def extract_file_info(file_path):
    info=os.stat(file_path)
    inode=info.st_ino
    device=info.st_dev
    full_info=(inode,device)
    return full_info

def creation_event(file_path):
    try:
        hash=hashlib.file_digest(open(file_path, "rb"),hashing_algorithm).hexdigest()
        file_info= extract_file_info(file_path)
        inode=file_info[0]
        device=file_info[1]
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

def modification_event(file_path,event_type):
    try:
        old_hash=consultar_hash(file_path)
        new_hash=hashlib.file_digest(open(file_path, "rb"),hashing_algorithm).hexdigest()
        file_info= extract_file_info(file_path)
        inode=file_info[0]
        device=file_info[1]
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


def updated_event(file_path):
    try:
        old_hash=consultar_hash(file_path)
        new_hash=hashlib.file_digest(open(file_path, "rb"),hashing_algorithm).hexdigest()
        file_info= extract_file_info(file_path)
        inode=file_info[0]
        device=file_info[1]
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


def store_hash(file_path):
    try:
        hash=hashlib.file_digest(open(file_path, "rb"),hashing_algorithm).hexdigest()
        info=os.stat(file_path)
        inode=info.st_ino
        device=info.st_dev
        conn = sqlite3.connect('hashes.db')
        c = conn.cursor()  
        consulta="INSERT INTO file_hashes (inode, hash, device, file_path) VALUES (?, ?, ?, ?)"
        c.execute(consulta, (inode,hash, device, file_path))
        print(f"[+] El hash es {hash}") 
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error al almacenar el hash: {e}")
        return False

def consultar_hash(file_path):
    info=os.stat(file_path)
    inode=info.st_ino
    conn = sqlite3.connect('hashes.db')
    res = conn.cursor()  
    consulta="SELECT * from file_hashes WHERE inode = ?"
    res.execute(consulta, (inode,))
    row=res.fetchone()
    return row[2]
 

def consultar_existencia_archivo(file_path):
    info=os.stat(file_path)
    inode=info.st_ino
    conn = sqlite3.connect('hashes.db')
    res = conn.cursor()  
    consulta="SELECT * from file_hashes WHERE inode = ?"
    res.execute(consulta, (inode,))
    if(res.fetchone()):
        return True
    else:        
        return False
    
def update_hash(file_path):
    try:
        hash=hashlib.file_digest(open(file_path, "rb"),hashing_algorithm).hexdigest()
        info=os.stat(file_path)
        inode=info.st_ino
        device=info.st_dev
        conn = sqlite3.connect('hashes.db')
        c = conn.cursor()  
        consulta="UPDATE file_hashes SET hash = ? WHERE inode = ? AND device = ?"
        c.execute(consulta, (hash, inode, device))
        print(f"[+] El nuevo hash es {hash}")
        conn.commit()
        conn.close()
        return c.rowcount > 0
    except Exception as e:
        print(f"Error al almacenar el hash: {e}")
        return False


def cambio_masivo_algoritmo_DB():
    
    conn = sqlite3.connect('hashes.db')
    c = conn.cursor()  
    c.execute("SELECT inode, file_path, device FROM file_hashes")
    rows=c.fetchall()
    print(rows)

    for inode, filepath, device in rows:
        
        with open(filepath, "rb") as f:
            if not os.path.exists(filepath):
                print(f"\n[-] El archivo {filepath} no existe, no se puede actualizar el hash\n")
                continue
            new_hash=hashlib.file_digest(f, hashing_algorithm).hexdigest()
            consulta=("UPDATE file_hashes SET hash= ? WHERE inode = ? AND device = ?")
            c.execute(consulta, (new_hash, inode, device))
            print(f"\n[+] El nuevo hash con el algorithmo {hashing_algorithm} es {new_hash}\n")
            conn.commit()
            if(c.rowcount > 0):
                print("\n[+] Cambio realizado con éxito\n")
            else:
                print("\n[-] No se pudo realizar la actualizacion masiva en la base de datos\n")

def cambiar_algoritmo_hashing(eleccion):
    global hashing_algorithm
    available_algorithms={
        1:"sha256",
        2:"sha512",
        3:"blake2b",
        4:"sha3_256"
    }
    hashing_algorithm= available_algorithms[eleccion]

def detect_hash_changes(file_path):
    local_db_hash=consultar_hash(file_path)
    new_hash=hashlib.file_digest(open(file_path, "rb"),hashing_algorithm).hexdigest()
    if(local_db_hash == new_hash):
        print("\n[+] Hashes son iguales.\n")
        return "VERIFIED"
    else:
        print("\n[+] ATENCION!! CAMBIO EN HASHES DETECTADO!!\n")
        return "MODIFIED"
    
def generate_individual_json_report():
    if not os.path.exists("reports/individual"):
        os.makedirs("reports/individual")
    conn = sqlite3.connect('hashes.db')
    c = conn.cursor()  
    #(event_id INTEGER, inode INTEGER, device TEXT, old_hash TEXT, new_hash TEXT, file_path TEXT, event_type TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(event_id))

    c.execute("SELECT inode, device, old_hash, new_hash, file_path, event_type, timestamp FROM integrity_events")
    data=c.fetchall()
    report={}
    print(f"\n\nLongitud de la data: {len(data)}\n\n")
    counter=0
    print(data)
    for row in data:
        #if row[5] == "MODIFIED":

        report={}
        report={
            "Event Type": row[5],
            "Inode": row[0],
            "Device": row[1],
            "old_hash": row[2],
            "new_hash": row[3],
            "file_path": row[4],
            "timestamp": row[-1]
        }

        report_name=f"reports/individual/report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}_{row[0]}_{counter}.json"
        counter+=1
        with open(report_name, "w") as f:
            json.dump(report,f,indent=4)

def generate_general_json_report():
    if not os.path.exists("reports/general"):
        os.makedirs("reports/general")
    conn = sqlite3.connect('hashes.db')
    c = conn.cursor()  
    #(event_id INTEGER, inode INTEGER, device TEXT, old_hash TEXT, new_hash TEXT, file_path TEXT, event_type TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(event_id))

    c.execute("SELECT inode, device, old_hash, new_hash, file_path, event_type, timestamp FROM integrity_events")
    data=c.fetchall()
    report={}
    reporte_general=[]
    for row in data:
        #if row[5] == "MODIFIED":

        report={
            "Event Type": row[5],
            "Inode": row[0],
            "Device": row[1],
            "old_hash": row[2],
            "new_hash": row[3],
            "file_path": row[4],
            "timestamp": row[-1]
        }
        reporte_general.append(report)

    report_name=f"reports/general/general_report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.json"
    with open(report_name, "w") as f:
        json.dump(reporte_general,f,indent=4)

def verify_reports_existence():
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

        

    

while True:
    set_DB()
    print("Bienvenido al sistema de integridad de archivos")
    print("1. Almacenar un nuevo archivo")
    print("2. Verificar el hash de un archivo")
    print("3. Actualizar el hash de un archivo")
    print("4. Cambiar algoritmo de hashing utilizado")
    print("5. Generar reporte")
    print("6. Salir")
    opcion=int(input("Ingrese la opción deseada: "))  

    if opcion==1:
        file_path=input("Ingrese la ruta del archivo a almacenar: ")
        if(consultar_existencia_archivo(file_path) == False):
            store_hash(file_path)
            print(f"\n[+] El hash se ha guardado correctamente\n")
            if (creation_event(file_path)):
                print("\n[+] Evento de creacion insertado\n")
        else:
            print(f"\n[+] El archivo ya existe en la base de datos\n")



    elif opcion==2:
        file_path=input("Ingrese la ruta del archivo a consultar: ")
        #Falta logica de comprobacion de existencia de archivo )
        flag=detect_hash_changes(file_path)
        if(modification_event(file_path, flag)):
            print("\n[+] Detección registrada en el sistema de reportes\n")
        else:
            print("\n[-] El registro del evento falló\n")
            
            

    elif opcion==3:
        file_path=input("Ingrese la ruta del archivo a actualizar: ")
        if(consultar_existencia_archivo(file_path) == True):
            update_hash(file_path)
            print(f"\n[+] El hash se ha actualizado correctamente\n")
        else:
            print(f"\n[+] El archivo no existe en la base de datos\n")
        if(updated_event(file_path)):
            print("\n[+] Actualización registrada en el sistema de reportes\n")
        else:
            print("\n[-] El registro del evento falló\n")


    elif opcion==4:
        print("Seleccione el nuevo algoritmo de hashing:")
        print("1. SHA-256")
        print("2. SHA-512")
        print("3. BLAKE2b")
        print("4. SHA3-256")
        eleccion=int(input("Ingrese la opción deseada: "))
        cambiar_algoritmo_hashing(eleccion)
        cambio_masivo_algoritmo_DB()

    elif opcion==5:
        print("Seleccione la opcion que desea:")
        print("1. Generar reporte general")
        print("2. Generar reportes individuales")
        eleccion=int(input("Ingrese la opción deseada: "))
        if(eleccion== 1):
            if(verify_reports_existence):
                generate_general_json_report()
            else:
                print("[-] ERROR. No hay reportes disponibles")
        else:
            if(verify_reports_existence):
                generate_individual_json_report()
            else:
                print("[-] ERROR. No hay reportes disponibles")
            
            
    elif opcion==6:
        print("[+] Saliendo del sistema...")
        break





