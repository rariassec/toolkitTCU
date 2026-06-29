from toolkitTCU.integrity_module.core.DatabaseManager import DatabaseManager
from toolkitTCU.integrity_module.core.FileIntegrityChecker import FileIntegrityChecker
from toolkitTCU.integrity_module.core.HashStorage import HashStorage
from toolkitTCU.integrity_module.events.EventManager import EventManager
from toolkitTCU.integrity_module.reports.ReportGenerator import ReportGenerator
from toolkitTCU.integrity_module.utils.FileHandler import FileHandler
from toolkitTCU.integrity_module.core.BackupFiles import BackupFiles
from toolkitTCU.integrity_module.core.PathTracker import PathTracker
from toolkitTCU.integrity_module.events.WatchdogEventHandler import EventHandler
from toolkitTCU.integrity_module.utils.LoadConfig import ConfigLoader, bootstrap_config
from toolkitTCU.integrity_module.events.Observer import file_observer
from toolkitTCU.integrity_module.utils.Logger import Logger
from toolkitTCU.integrity_module.core.ChangesManager import ChangesManager
from toolkitTCU.integrity_module.core.AlertManager import AlertManager
import os
from toolkitTCU.integrity_module.core.stats import Stats
from toolkitTCU.integrity_module.utils.SetupWizard import SetupWizard
from toolkitTCU.integrity_module.utils.AlertConfig import configure_email_alerts
class FileIntegritySystem:

    def __init__(self):
        bootstrap_config()
        self.load_config= ConfigLoader()
        self.setup_wizard = SetupWizard()
        self.setup_wizard.maybe_run()
        self.log=Logger(self.load_config)
        self.db_manager= DatabaseManager(self.load_config)
        self.stats=Stats(self.db_manager)
        self.file_handler=FileHandler(self.db_manager, self.log)
        self.alert_manager=AlertManager(self.load_config)
        self.backup_files = BackupFiles(self.db_manager, self.file_handler, self.log, self.load_config)
        self.hash_storage = HashStorage(self.db_manager, self.file_handler, self.log, self.backup_files, self.load_config)
        self.event_manager = EventManager(self.db_manager, self.hash_storage, self.file_handler, self.log, self.load_config)
        self.changes_manager=ChangesManager(self.db_manager, self.hash_storage, self.event_manager)
        self.file_integrity_checker=FileIntegrityChecker(self.hash_storage, self.file_handler, self.db_manager, self.log, self.load_config)
        self.report_generator = ReportGenerator(self.db_manager, self.log, self.load_config, self.stats)
        self.path_tracker=PathTracker(self.db_manager, self.load_config)
        self.event_handler = EventHandler(self.event_manager, self.file_integrity_checker, self.hash_storage, self.backup_files, self.db_manager, self.path_tracker, self.log, self.alert_manager)
        self.observer = file_observer(self.event_handler, self.load_config.load_config())
        self.running = True
    def run_background_services(self):
            self.db_manager.set_DB()
            self.observer.start()
            self.path_tracker.start()
            self.backup_files.run()
            self.hash_storage.start_store_default_baseline()
            self.file_integrity_checker.begin_detect_changes_at_start()

    def run(self):
        self.run_background_services()
        while True:
            print("\n============================================================")
            print(" INTEGRIDAD DE ARCHIVOS (FIM)")
            print("============================================================")
            print(" Este modulo vigila que tus archivos no sean alterados sin")
            print(" autorizacion. Guarda una huella (hash) de cada archivo y avisa")
            print(" si algo cambia, se crea o se elimina en las carpetas vigiladas.")
            print("------------------------------------------------------------")
            print(" 1. Almacenar hash       guarda la huella de un archivo o carpeta")
            print("                         como referencia para comparaciones futuras")
            print(" 2. Deteccion manual     compara el estado actual contra las huellas")
            print("                         guardadas y reporta los cambios")
            print(" 3. Baseline             revisa y gestiona los cambios detectados")
            print(" 4. Estadisticas         metricas y graficos del monitoreo")
            print(" 5. Generar reporte      exporta el historial en JSON, TXT o PDF")
            print(" 6. Reconfigurar         cambia las carpetas vigiladas")
            print(" 7. Alertas por correo   configura el envio de alertas por email")
            print(" 0. Volver")
            raw = input("\nSeleccione una opcion: ").strip()
            if not raw.isdigit():
                print("\n[-] Opcion invalida, intente nuevamente.")
                continue
            opcion=int(raw)

            if opcion==1:
                print("\n--- Almacenar hash ---")
                print("Calcula la huella (hash) de un archivo o carpeta y la guarda como")
                print("referencia. Asi el sistema podra detectar despues si ese contenido")
                print("cambia, se elimina o se altera sin autorizacion.")
                path=input("\nRuta del archivo o carpeta a proteger: ").strip()
                if not os.path.exists(path):
                    print("\n[-] La ruta indicada no existe. Verifique e intente de nuevo.")
                    continue
                print("\nAlgoritmo de hash a utilizar:")
                print(" 1. SHA-256 (recomendado)")
                print(" 2. SHA-512")
                print(" 3. BLAKE2b")
                print(" 4. SHA3-256")
                algorithms = {
                    1: "sha256",
                    2: "sha512",
                    3: "blake2b",
                    4: "sha3_256"
                }
                raw_algo = input("Seleccione una opcion [1]: ").strip() or "1"
                algorithm = algorithms.get(int(raw_algo), "sha256") if raw_algo.isdigit() else "sha256"
                if(self.hash_storage.consult_path_hash_existence_in_db(path) == False or self.hash_storage.consult_path_hash_existence_in_db(path) == []):
                    self.hash_storage.store_hash(path, algorithm)
                    print(f"\n[+] Listo. El archivo quedo protegido con {algorithm.upper()}.")
                    print("    A partir de ahora se detectara cualquier cambio en el.\n")
                    self.event_manager.generate_creation_event(path, "CREATED")
                else:
                    print(f"\n[+] La ruta especificada ya tiene al menos un hash asociado en la base de datos\n")

            elif opcion==2:
                print("\n--- Deteccion manual de cambios ---")
                print("Compara el estado actual de los archivos contra las huellas ya")
                print("guardadas y reporta si algo fue modificado, creado o eliminado.")
                print("A continuacion puede afinar el alcance del analisis.")
                path=input("\nRuta del archivo o carpeta a verificar: ")
                subdirectories=input("Incluir subcarpetas? [S/N]: ").upper() =='S'
                hidden_files=input("Verificar archivos ocultos? [S/N]: ").upper()== 'S'
                deleted_files=input("Incluir archivos eliminados? [S/N]: ").upper() == 'S'
                automatic_report=input("Generar un reporte automatico al finalizar? [S/N]: ").upper() == 'S'
                extensions=input("Extensiones a incluir separadas por coma (vacio para todas): ")
                whitelist = [ext.strip().lower() for ext in extensions.split(",")] if extensions != "" else []
                whitelist.append("")
                file_size=input("Ingrese el tamano maximo del archivo: ")
                if file_size.strip() and file_size.isdigit():
                    max_size = int(file_size)
                else:
                    max_size = None
                event, scan_session_id=self.file_integrity_checker.detect_any_hash_change(path, subdirectories, hidden_files, deleted_files, automatic_report, whitelist, max_size )
                if isinstance(event, dict) and event == {}:
                    print(f"\n[+] Hashes son iguales. Ruta: {path}\n")
                elif  event == "VERIFIED":
                    print(f"\n[+] Hashes son iguales. Ruta: {path}\n")
                elif event == "DELETED":
                    print(f"\n[-] La Ruta: {path} ha sido eliminada\n")
                else:
                    print(f"\n[-] Hashes NO son iguales. Ruta: {path}\n")
                self.event_manager.generate_modification_event(path,event,scan_session_id)

            elif opcion==3:
                self.changes_manager.show_all_changes()

            elif opcion==4:
                print(f"Archivos monitoreados: {self.stats.get_monitored_files()}")
                last_scan_date, last_scan_time=self.stats.get_last_scan_date_and_time()
                print(f"Ultimo escaneo: {last_scan_date} | {last_scan_time}")
                print(f"Cambios detectados: {self.stats.get_detected_changes()}")
                print(f"Tiempo promedio de escaneo: {self.stats.get_avg_scan_time()}")
                print(f"Estado del sistema: {self.stats.get_system_state()}")
                self.stats.display_events_table()
                self.stats.changes_last_7_days_graph()
                self.stats.afected_files_extensions_graph()
                self.stats.tendency_30d_graph()

            elif opcion == 5:
                print("\n--- Generar reporte ---")
                print("Exporta el historial de cambios de integridad detectados.")
                print("Los reportes se guardan en la carpeta reportes del toolkit.")
                print(" 1. Reporte general (todos los eventos en un archivo)")
                print(" 2. Reportes individuales (un archivo por evento)")
                print(" 3. Resumen ejecutivo en PDF (con graficos y recomendaciones)")
                raw_eleccion = input("\nSeleccione una opcion: ").strip()
                if not raw_eleccion.isdigit():
                    print("\n[-] Opcion invalida\n")
                    continue
                eleccion = int(raw_eleccion)

                if eleccion in [1, 2]:
                    print("\nSeleccione el formato:")
                    print(" 1. JSON")
                    print(" 2. TXT")
                    raw_formato = input("Seleccione una opcion: ").strip()
                    formato = int(raw_formato) if raw_formato.isdigit() else 0

                    if formato not in [1, 2]:
                        print("\n[-] Opcion de formato invalida\n")
                    elif not self.db_manager.consult_reports_existence():
                        print("\n[-] ERROR. No hay reportes disponibles\n")
                    else:
                        if eleccion == 1:
                            if formato == 1:
                                exito = self.report_generator.generate_general_json_report()
                                mensaje = "reporte general en formato JSON"
                            else:
                                exito = self.report_generator.generate_general_txt_report()
                                mensaje = "reporte general en formato TXT"
                        else:
                            if formato == 1:
                                exito = self.report_generator.generate_individual_json_report()
                                mensaje = "reportes individuales en formato JSON"
                            else:
                                exito = self.report_generator.generate_individual_txt_report()
                                mensaje = "reportes individuales en formato TXT"

                        if exito:
                            print(f"\n[+] Se ha(n) generado {mensaje} exitosamente\n")
                        else:
                            print(f"\n[-] ERROR. No se pudo generar {mensaje}\n")

                elif eleccion == 3:
                    self.report_generator.generate_executive_summary()

                else:
                    print("\n[-] Opcion invalida\n")

            elif opcion==6:
                self.setup_wizard.run()
                print("[i] Reinicie el sistema para aplicar la nueva configuracion de monitoreo")

            elif opcion==7:
                configure_email_alerts()
                print("[i] Reinicie el modulo de integridad para que tome las nuevas credenciales")

            elif opcion==0:
                print("[+] Deteniendo servicios y volviendo...")
                self.observer.stop()
                self.path_tracker.stop()
                self.backup_files.stop()
                break

            else:
                print("\n[-] Opcion invalida, intente nuevamente.")

if __name__ == "__main__":
    sistema = FileIntegritySystem()
    sistema.run()
