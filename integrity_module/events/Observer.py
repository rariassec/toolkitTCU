from watchdog.observers import Observer
import os

class file_observer:

    def __init__(self, event_handler, loadedConfig):
        self.event_handler = event_handler
        self.observer = Observer()
        self.loadedConfig = loadedConfig

    def start(self):
        for dict in self.loadedConfig.get("watch", []):
            recursive = dict.get("recursive", True)
            for path in dict.get("paths", []):
                if not os.path.isdir(path):
                    print(f"[!] Ruta de monitoreo inexistente, se omite: {path}")
                    continue
                self.observer.schedule(self.event_handler, path, recursive=recursive)
                print("Observador iniciado en el directorio:", path)
        self.observer.start()

    def stop(self):
        self.observer.stop()
        self.observer.join()
        print("Observador detenido.")
