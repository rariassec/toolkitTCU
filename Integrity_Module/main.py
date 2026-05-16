from core.DatabaseManager import DatabaseManager
from core.FileIntegrityChecker import FileIntegrityChecker
from core.HashStorage import HashStorage
from events.EventManager import EventManager
from reports.ReportGenerator import ReportGenerator
from utils.FileHandler import FileHandler

class FileIntegritySystem:
    def __init__(self):
        self.db_manager= DatabaseManager()
        self.file_handler=FileHandler(self.db_manager)
        self.hash_storage = HashStorage(self.db_manager, self.file_handler)
        self.file_integrity_checker=FileIntegrityChecker(self.hash_storage, self.file_handler, self.db_manager)
        self.event_manager = EventManager(self.db_manager, self.hash_storage, self.file_handler)
        self.report_generator = ReportGenerator(self.db_manager)
        
    def run(self):


        while True:
            self.db_manager.set_DB()
            print("Bienvenido al sistema de integridad de archivos")
            print("1. Almacenar hash")
            print("2. Verificar hash")
            print("3. Actualizar hash")
            print("4. Cambiar algoritmo de hashing utilizado")
            print("5. Generar reporte")
            print("6. Salir")
            opcion=int(input("Ingrese la opción deseada: "))  

            if opcion==1:
                path=input("Ingrese la ruta del archivo a almacenar: ")
                path_existence=self.hash_storage.consult_path_hash_existence_in_db(path)
                print(path_existence)
                if(self.hash_storage.consult_path_hash_existence_in_db(path) == False or self.hash_storage.consult_path_hash_existence_in_db(path) == []):
                    self.hash_storage.store_hash(path)
                    print(f"\n[+] El hash se ha guardado correctamente\n")
                    self.event_manager.generate_creation_event(path)
                else:
                    print(f"\n[+] La ruta especificada ya tiene al menos un hash asociado en la base de datos\n")



            elif opcion==2:
                path=input("Ingrese la ruta del archivo a consultar: ")
                #Falta logica de comprobacion de existencia de archivo )
                event=self.file_integrity_checker.detect_any_hash_change(path)
                self.event_manager.generate_modification_event(path,event)
                    
                    

            elif opcion==3:
                path=input("Ingrese la ruta del archivo a actualizar: ")
                event=None
                if(self.hash_storage.consult_path_hash_existence_in_db(path) == True):
                    event=self.hash_storage.execute_hash_update(path)
                else:
                    print(f"\n[+] El archivo no existe en la base de datos\n")
                    self.event_manager.generate_updated_event(path, event)
                    


            elif opcion==4:
                print("Seleccione el nuevo algoritmo de hashing:")
                print("1. SHA-256")
                print("2. SHA-512")
                print("3. BLAKE2b")
                print("4. SHA3-256")
                eleccion=int(input("Ingrese la opción deseada: "))
                self.hash_storage.change_hashing_algorithm(eleccion)
                self.hash_storage.change_algorithm_in_all_db()

            elif opcion==5:
                print("Seleccione la opcion que desea:")
                print("1. Generar reporte general")
                print("2. Generar reportes individuales")
                eleccion=int(input("Ingrese la opción deseada: "))
                if(eleccion== 1):
                    if(self.db_manager.consult_reports_existence()):
                        self.report_generator.generate_general_json_report()
                    else:
                        print("[-] ERROR. No hay reportes disponibles")
                else:
                    if(self.db_manager.consult_reports_existence()):
                        self.report_generator.generate_individual_json_report()
                    else:
                        print("[-] ERROR. No hay reportes disponibles")
                
                
            elif opcion==6:
                print("[+] Saliendo del sistema...")
                break

if __name__ == "__main__":
    sistema = FileIntegritySystem()
    sistema.run()
