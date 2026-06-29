import os

_NETWORK_MODULE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CREDENTIALS_FILE = os.path.join(_NETWORK_MODULE_DIR, "vt_credentials.env")

def load_vt_key():
    if os.environ.get("VT_API_KEY"):
        return os.environ["VT_API_KEY"]
    if os.path.isfile(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("VT_API_KEY="):
                    key = line.split("=", 1)[1].strip()
                    if key:
                        os.environ["VT_API_KEY"] = key
                        return key
    return ""

def save_vt_key(key):
    import toolkitTCU.network_module.core.config as config
    os.makedirs(os.path.dirname(CREDENTIALS_FILE), exist_ok=True)
    with open(CREDENTIALS_FILE, "w") as f:
        f.write(f"VT_API_KEY={key}\n")
    os.environ["VT_API_KEY"] = key
    config.VT_API_KEY = key

def configure_vt_api_key_menu():
    import toolkitTCU.network_module.core.config as config

    print("\n============================================================")
    print(" CONFIGURAR API KEY DE VIRUSTOTAL")
    print("============================================================")
    print(" VirusTotal permite consultar la reputacion de IPs en el")
    print(" analisis DNS y en la deteccion de conexiones sospechosas.")
    print(" La cuenta gratuita permite 4 consultas por minuto.")
    print(" Solicita tu clave en: https://www.virustotal.com/gui/my-apikey")
    print("------------------------------------------------------------")

    current = config.VT_API_KEY
    if current:
        print(f" Key actual: {current[:8]}{'*' * (len(current) - 8)}")
    else:
        print(" Key actual: no configurada")

    print("\n 1. Ingresar / actualizar API Key")
    print(" 2. Eliminar API Key guardada")
    print(" 0. Volver")

    option = input("\nSeleccione una opcion: ").strip()

    if option == "1":
        key = input("\nIngrese su API Key de VirusTotal: ").strip()
        if not key:
            print("\n[-] No se ingreso ninguna clave.")
            return
        save_vt_key(key)
        print("\n[+] API Key guardada correctamente.")
        print(f"    Archivo: {CREDENTIALS_FILE}")
        print("    Las consultas a VirusTotal estan activas para esta sesion.")

    elif option == "2":
        if os.path.isfile(CREDENTIALS_FILE):
            os.remove(CREDENTIALS_FILE)
        os.environ.pop("VT_API_KEY", None)
        import toolkitTCU.network_module.core.config as config
        config.VT_API_KEY = ""
        print("\n[+] API Key eliminada.")

    elif option == "0":
        return
    else:
        print("\n[-] Opcion invalida.")
