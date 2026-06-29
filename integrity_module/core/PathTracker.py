import threading
import time
import os
import traceback
from toolkitTCU.integrity_module.core.DatabaseManager import DatabaseManager
from toolkitTCU.integrity_module.utils.LoadConfig import ConfigLoader

class PathTracker:
    def __init__(self, db_manager: DatabaseManager, load_config: ConfigLoader):
        self.running = True
        self.loaded_config = load_config.load_config()
        self.interval = self.loaded_config.get("scan", {}).get("interval_seconds", 10)
        self.db_manager = db_manager
        self.process = threading.Thread(target=self.verify_path_changes, daemon=True)

    def _get_watch_paths(self):
        paths = []
        for entry in self.loaded_config.get("watch", []):
            for path in entry.get("paths", []):
                if os.path.isdir(path):
                    paths.append(path)
        return paths

    def verify_path_changes(self):
        all_inodes = self.db_manager.consulta_all_file_inodes()
        self.search_file_in_disk(all_inodes)

    def search_file_in_disk(self, all_inodes):
        try:
            buffer_files = []
            all_paths = []
            found = {}
            for watch_path in self._get_watch_paths():
                for root, dirs, files in os.walk(watch_path):
                    data = (root, files)
                    buffer_files.append(data)

            for data_tuple in buffer_files:
                path = data_tuple[0]
                for file in data_tuple[1]:
                    full_path = os.path.join(path, file)
                    all_paths.append(full_path)

            for path in all_paths:
                stat_info = os.stat(path)
                inode = stat_info.st_ino
                if inode in all_inodes:
                    found[inode] = path
                    self.db_manager.update_path(path, stat_info.st_ino, stat_info.st_dev)
            return found
        except Exception as e:
            print(f"\n[-] Ocurrio un error al buscar archivos en el disco: {e}\n")
            print(traceback.format_exc())
            return False

    def search_for_path_changes(self):
        while self.running:
            self.verify_path_changes()
            time.sleep(self.interval)

    def start(self):
        try:
            self.process.start()
        except Exception as e:
            print(f"\n[-] Ocurrio un error en el proceso de seguimiento de rutas: {e}\n")
            print(traceback.format_exc())

    def stop(self):
        self.running = False
        if self.process.is_alive():
            self.process.join()
        print("\n[+] Proceso de tracking detenido\n")
