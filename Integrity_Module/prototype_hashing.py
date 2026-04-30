import sqlite3
import hashlib  
import os

hashing_algorithm ="sha256"
def create_database():
    conn = sqlite3.connect('hashes.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS file_hashes
                 (hash_id INTEGER, inode INTEGER, hash TEXT, file_path TEXT, device TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(inode, device))''')
    conn.commit()
    conn.close()
    
def store_hash(file_path):
    try:
        create_database()
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
    if not os.path.exists("hashes.db"):
        create_database()
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
    

    

while True:
    print("Bienvenido al sistema de integridad de archivos")
    print("1. Almacenar un nuevo archivo")
    print("2. Consultar el hash de un archivo")
    print("3. Actualizar el hash de un archivo")
    print("4. Cambiar algoritmo de hashing utilizado")
    print("5. Salir")
    opcion=int(input("Ingrese la opción deseada: "))  

    if opcion==1:
        

        file_path=input("Ingrese la ruta del archivo a almacenar: ")
        if(consultar_existencia_archivo(file_path) == False):
            store_hash(file_path)
            print(f"\n[+] El hash se ha guardado correctamente\n")
        else:
            print(f"\n[+] El archivo ya existe en la base de datos\n")



    elif opcion==2:
        file_path=input("Ingrese la ruta del archivo a consultar: ")
        local_db_hash=consultar_hash(file_path)
        if(local_db_hash == hashlib.file_digest(open(file_path, "rb"),hashing_algorithm).hexdigest()):
            print("\n[+] Hashes son iguales.\n")
        else:
            print("\n[+] ATENCION!! CAMBIO EN HASHES DETECTADO!!\n")

    elif opcion==3:
        file_path=input("Ingrese la ruta del archivo a actualizar: ")
        if(consultar_existencia_archivo(file_path) == True):
            update_hash(file_path)
            print(f"\n[+] El hash se ha actualizado correctamente\n")
        else:
            print(f"\n[+] El archivo no existe en la base de datos\n")


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
        print("[+] Saliendo del sistema...")
        break





