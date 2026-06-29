
import json
import os

from toolkitTCU.integrity_module.utils.LoadConfig import (
    DEFAULT_CONFIG_FILE,
    ensure_config_exists,
)

_ALGORITHMS = {
    "1": "sha256",
    "2": "sha512",
    "3": "blake2b",
    "4": "sha3_256",
}

class SetupWizard:

    def __init__(self, config_path=DEFAULT_CONFIG_FILE):
        self.config_path = config_path
        self.marker_path = os.path.join(os.path.dirname(config_path), ".initialized")

    def is_configured(self):
        return os.path.exists(self.marker_path)

    def maybe_run(self):
        if not self.is_configured():
            print("\n[i] Primer arranque detectado. Vamos a configurar el monitoreo.")
            self.run()

    def _read_raw_config(self):
        try:
            if self.config_path == DEFAULT_CONFIG_FILE:
                ensure_config_exists()
            with open(self.config_path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception as error:
            print(f"[-] No se pudo leer la configuracion: {error}")
            return {}

    def _write_raw_config(self, config):
        with open(self.config_path, "w", encoding="utf-8") as fh:
            json.dump(config, fh, indent=4, ensure_ascii=False)

    def _prompt_directories(self):
        print("\nIngrese las carpetas que desea proteger.")
        print("Puede indicar varias separadas por coma. Ejemplo: /var/www, /etc")
        while True:
            raw = input("Carpetas a monitorear: ").strip()
            if not raw:
                print("  Debe indicar al menos una carpeta.")
                continue
            candidates = [p.strip() for p in raw.split(",") if p.strip()]
            valid = [p for p in candidates if os.path.isdir(p)]
            invalid = [p for p in candidates if not os.path.isdir(p)]
            for p in invalid:
                print(f"  [!] No existe o no es carpeta, se omite: {p}")
            if valid:
                return valid
            print("  Ninguna carpeta es valida. Intente nuevamente.")

    def _prompt_yes_no(self, question, default_yes=True):
        suffix = "(S/n)" if default_yes else "(s/N)"
        answer = input(f"{question} {suffix}: ").strip().lower()
        if not answer:
            return default_yes
        return answer in ("s", "si", "y", "yes")

    def _prompt_algorithm(self):
        print("\nAlgoritmo de hash por defecto")
        print("1. sha256 (recomendado)")
        print("2. sha512")
        print("3. blake2b")
        print("4. sha3_256")
        choice = input("Seleccione opcion [1]: ").strip() or "1"
        return _ALGORITHMS.get(choice, "sha256")

    def _prompt_interval(self):
        raw = input("\nIntervalo de escaneo en segundos [10]: ").strip()
        if raw.isdigit() and int(raw) > 0:
            return int(raw)
        return 10

    def run(self):
        print("\n============================================================")
        print(" ASISTENTE DE CONFIGURACION - INTEGRIDAD DE ARCHIVOS")
        print("============================================================")

        config = self._read_raw_config()

        directories = self._prompt_directories()
        recursive = self._prompt_yes_no("Incluir subcarpetas (recursivo)", default_yes=True)
        algorithm = self._prompt_algorithm()
        interval = self._prompt_interval()
        email_alerts = self._prompt_yes_no("Habilitar alertas por correo", default_yes=False)

        config["watch"] = [{"paths": directories, "recursive": recursive}]
        config.setdefault("default_baseline", {})["paths"] = directories
        config["default_hashing_algorithm"] = algorithm
        config.setdefault("scan", {})["interval_seconds"] = interval
        config.setdefault("alerts", {})["email_enabled"] = email_alerts

        self._write_raw_config(config)

        try:
            with open(self.marker_path, "w", encoding="utf-8") as fh:
                fh.write("configurado\n")
        except Exception as error:
            print(f"[-] No se pudo crear el marcador de configuracion: {error}")

        print("\n[+] Configuracion guardada correctamente.")
        print(f"    Carpetas monitoreadas: {', '.join(directories)}")
        print(f"    Recursivo: {'si' if recursive else 'no'} | Algoritmo: {algorithm} | Intervalo: {interval}s")
        print(f"    Alertas por correo: {'si' if email_alerts else 'no'}\n")
