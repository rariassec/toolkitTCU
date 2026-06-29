
import os
import shutil
import subprocess
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REQUIREMENTS = os.path.join(BASE_DIR, "requirements.txt")

def print_header(text):
    print("\n" + "=" * 60)
    print(text)
    print("=" * 60)

def install_python_dependencies():
    print_header("instalando dependencias de python")
    if not os.path.exists(REQUIREMENTS):
        print(f"[-] no se encontro el archivo de requisitos en {REQUIREMENTS}")
        return False
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "-r", REQUIREMENTS]
        )
        print("\n[+] dependencias de python instaladas correctamente")
        return True
    except subprocess.CalledProcessError as error:
        print(f"\n[-] fallo la instalacion de dependencias: {error}")
        return False

def check_system_requirements():
    print_header("verificando requisitos del sistema")
    ok = True

    if shutil.which("nmap"):
        print("[+] nmap encontrado en el sistema")
    else:
        ok = False
        print("[!] nmap no esta instalado (lo usa el modulo de red)")
        print("    debian/ubuntu : sudo apt install nmap")
        print("    fedora        : sudo dnf install nmap")
        print("    arch          : sudo pacman -S nmap")
        print("    macos         : brew install nmap")

    print("\n[i] algunos escaneos de red y la captura de trafico requieren")
    print("    privilegios de administrador (sudo)")
    return ok

def main():
    print_header("instalador del toolkit tcu")
    print(f"interprete de python : {sys.executable}")
    print(f"version              : {sys.version.split()[0]}")

    deps_ok = install_python_dependencies()
    sys_ok = check_system_requirements()

    print_header("resultado de la instalacion")
    if deps_ok and sys_ok:
        print("[+] todo listo. puede ejecutar el toolkit con:")
    else:
        print("[!] instalacion completada con advertencias. revise los mensajes anteriores.")
        print("    una vez resueltas, ejecute el toolkit con:")
    print("\n    python run_web.py")
    print("    (para escaneos de red con privilegios: sudo $(which python) run_web.py\n")
    return 0 if (deps_ok and sys_ok) else 1

if __name__ == "__main__":
    sys.exit(main())
