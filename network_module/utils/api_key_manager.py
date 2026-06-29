
import os

from toolkitTCU.network_module.utils.vt_key_manager import configure_vt_api_key_menu

_NETWORK_MODULE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NVD_CREDENTIALS_FILE = os.path.join(_NETWORK_MODULE_DIR, "nvd_credentials.env")

def load_nvd_key():
    if os.environ.get("NVD_API_KEY"):
        return os.environ["NVD_API_KEY"]
    if os.path.isfile(NVD_CREDENTIALS_FILE):
        with open(NVD_CREDENTIALS_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("NVD_API_KEY="):
                    key = line.split("=", 1)[1].strip()
                    if key:
                        os.environ["NVD_API_KEY"] = key
                        return key
    return ""

def save_nvd_key(key):
    import toolkitTCU.network_module.core.config as config
    os.makedirs(os.path.dirname(NVD_CREDENTIALS_FILE), exist_ok=True)
    with open(NVD_CREDENTIALS_FILE, "w") as f:
        f.write(f"NVD_API_KEY={key}\n")
    os.environ["NVD_API_KEY"] = key
    config.NVD_API_KEY = key
    config.NVD_REQUEST_INTERVAL = config.nvd_interval_for_key(bool(key))

def delete_nvd_key():
    import toolkitTCU.network_module.core.config as config
    if os.path.isfile(NVD_CREDENTIALS_FILE):
        os.remove(NVD_CREDENTIALS_FILE)
    os.environ.pop("NVD_API_KEY", None)
    config.NVD_API_KEY = ""
    config.NVD_REQUEST_INTERVAL = config.nvd_interval_for_key(False)

def configure_nvd_api_key_menu():
    import toolkitTCU.network_module.core.config as config

    print("\n============================================================")
    print(" CONFIGURAR API KEY DEL NVD (National Vulnerability Database)")
    print("============================================================")
    print(" El NVD se usa en la deteccion de servicios vulnerables (CVEs).")
    print(" La clave es OPCIONAL: sin ella se sigue usando el endpoint")
    print(" publico del NVD, pero con un limite de tasa mas estricto")
    print(" (5 consultas / 30 s). Con clave sube a 50 consultas / 30 s,")
    print(" lo que reduce los errores 503 por exceso de peticiones.")
    print(" Solicita tu clave en: https://nvd.nist.gov/developers/request-an-api-key")
    print("------------------------------------------------------------")

    current = config.NVD_API_KEY
    if current:
        print(f" Key actual: {current[:8]}{'*' * (len(current) - 8)}")
    else:
        print(" Key actual: no configurada (se usa el endpoint publico sin clave)")

    print("\n 1. Ingresar / actualizar API Key")
    print(" 2. Eliminar API Key guardada")
    print(" 0. Volver")

    option = input("\nSeleccione una opcion: ").strip()

    if option == "1":
        key = input("\nIngrese su API Key del NVD: ").strip()
        if not key:
            print("\n[-] No se ingreso ninguna clave.")
            return
        save_nvd_key(key)
        print("\n[+] API Key guardada correctamente.")
        print(f"    Archivo: {NVD_CREDENTIALS_FILE}")
        print("    Las consultas al NVD usaran el limite de tasa ampliado en esta sesion.")

    elif option == "2":
        delete_nvd_key()
        print("\n[+] API Key eliminada. Se seguira usando el endpoint publico sin clave.")

    elif option == "0":
        return
    else:
        print("\n[-] Opcion invalida.")

def configure_api_keys_menu():
    while True:
        print("\n============================================================")
        print(" CONFIGURAR API KEYS")
        print("============================================================")
        print(" Elija que clave desea cargar o gestionar.")
        print("------------------------------------------------------------")
        print(" 1. VirusTotal   reputacion de IPs (DNS y conexiones sospechosas)")
        print("                 solicitar: https://www.virustotal.com/gui/my-apikey")
        print(" 2. NVD          CVEs de servicios vulnerables (opcional)")
        print("                 solicitar: https://nvd.nist.gov/developers/request-an-api-key")
        print(" 0. Volver")

        option = input("\nSeleccione una opcion: ").strip()

        if option == "1":
            configure_vt_api_key_menu()
        elif option == "2":
            configure_nvd_api_key_menu()
        elif option == "0":
            return
        else:
            print("\n[-] Opcion invalida, intente nuevamente.")
