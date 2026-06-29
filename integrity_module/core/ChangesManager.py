from toolkitTCU.integrity_module.core.DatabaseManager import DatabaseManager
import shutil
import os
import traceback
from toolkitTCU.integrity_module.core.HashStorage import HashStorage
from toolkitTCU.integrity_module.events.EventManager import EventManager

class ChangesManager():

    def __init__(self, db_manager: DatabaseManager, hash_storage: HashStorage, event_manager: EventManager):
        self.db_manager = db_manager
        self.hash_storage = hash_storage
        self.event_manager = event_manager

    def show_all_changes(self):
        salir = True
        while salir:
            try:
                all_changes = self.db_manager.consult_all_changes()
                if not all_changes:
                    print("\n[+] No hay cambios pendientes\n")
                    return

                print(f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                         CAMBIOS PENDIENTES                                   ║
╠════╦══════════════════════════════════════════════════╦══════════════════════╣
║ #  ║ Ruta                                             ║ Ultimo evento        ║
╠════╬══════════════════════════════════════════════════╬══════════════════════╣""")

                for i, change in enumerate(all_changes, 1):
                    file_name = os.path.basename(change['file_path'])
                    event = change.get('status', 'MODIFIED')
                    print(f"║ {i:<2} ║ {file_name:<44}     ║ {event:<20} ║")

                print("""╚════╩══════════════════════════════════════════════════╩══════════════════════╝

            [1-{}] Seleccionar archivo  [S] Salir""".format(len(all_changes)))

                choice = input("\nOpcion: ")

                if choice.upper() == 'S':
                    salir = False
                    continue

                if choice != "":
                    idx = int(choice) - 1
                    if idx < 0 or idx >= len(all_changes):
                        print("Seleccion invalida.")
                        continue
                    file_changes = all_changes[idx]
                    print("1. Restaurar")
                    print("2. Actualizar")
                    print("3. Salir")
                    action_choice = int(input("\nOpcion: "))
                    if action_choice == 1:
                        self.restore_changes(file_changes)
                    elif action_choice == 2:
                        self.update_changes(file_changes)
            except Exception as e:
                print(f"Error en show_all_changes: {e}")
                print(traceback.format_exc())
                salir = False

    def restore_changes(self, file_changes):
        try:
            original_inode = file_changes["inode"]
            original_device = file_changes["device"]
            original_path = file_changes["file_path"]
            backup_file = self.db_manager.consult_all_info_backup_file(original_inode, original_device)
            if not backup_file:
                print("[-] No se encontro un archivo de backup para restaurar.")
                return
            backup_path = backup_file["backup_path"]
            backup_inode = backup_file["backup_inode"]
            backup_hash = backup_file["hash"]
            if(shutil.move(backup_path, original_path)):
                self.db_manager.update_file_info_according_backup(original_inode, backup_inode, backup_hash)
                print("Archivo restaurado con exito")
        except Exception as e:
            print(f"Error en restore_changes: {e}")
            print(traceback.format_exc())

    def update_changes(self, file_changes):
        try:
            path = file_changes["file_path"]
            inode = file_changes["inode"]
            event = self.hash_storage.execute_hash_update(path)
            self.db_manager.update_file_hash_status(inode, "verified")
            self.event_manager.generate_updated_event(path, event)
            print("Hash de archivo actualizado a verificado con exito")
        except Exception as e:
            print(f"Error en update_changes: {e}")
            print(traceback.format_exc())

