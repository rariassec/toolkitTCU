
import os
import hashlib

def recursivity(file_path):
    all_files=[]
    new_all_files=[]
    for root, dirs, files in os.walk(file_path):
        data=(root,files)
        all_files.append(data)
        
            

    for data_tuple in all_files:
        path=data_tuple[0]
        for file in data_tuple[1]:
            full_path=path+"/"+file
            new_all_files.append(full_path)

    for ruta in new_all_files:
        with open(ruta, "rb") as f:
            hash=hashlib.file_digest(f,"sha256").hexdigest()
            print(f"\nEl hash calculado para el arhivo {ruta} es {hash}\n")
            f.close()
    return new_all_files


file_path=input("Ingrese el archivo o directorio a hashear: ")

all_files=recursivity(file_path)

#print(all_files)