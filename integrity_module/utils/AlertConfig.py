
import getpass
import json
import os

from toolkitTCU.integrity_module.utils.LoadConfig import (
    MODULE_DIR,
    DEFAULT_CONFIG_FILE,
    ensure_config_exists,
)

CREDENTIALS_FILE = os.path.join(MODULE_DIR, "credentials.env")

def _set_email_enabled(valor):
    ensure_config_exists()
    with open(DEFAULT_CONFIG_FILE, "r", encoding="utf-8") as fh:
        cfg = json.load(fh)
    cfg.setdefault("alerts", {})["email_enabled"] = valor
    with open(DEFAULT_CONFIG_FILE, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=4, ensure_ascii=False)

def configure_email_alerts():
    print("\n============================================================")
    print(" CONFIGURAR ALERTAS POR CORREO")
    print("============================================================")
    print(" El modulo de integridad puede enviar un correo cuando detecta un")
    print(" cambio en los archivos vigilados.")
    print(" El envio usa Gmail (smtp.gmail.com), por lo que el correo emisor")
    print(" debe tener la verificacion en dos pasos activada y usar una")
    print(" contrasena de aplicacion (no la contrasena normal de la cuenta).")
    print("------------------------------------------------------------")

    sender = input("Correo emisor (desde donde se envian las alertas): ").strip()
    if not sender:
        print("\n[-] Configuracion cancelada: el correo emisor no puede estar vacio.")
        return
    password = getpass.getpass("Contrasena de aplicacion del emisor (no se mostrara): ").strip()
    if not password:
        print("\n[-] Configuracion cancelada: la contrasena no puede estar vacia.")
        return
    receiver = input("Correo destinatario (donde se reciben las alertas): ").strip()
    if not receiver:
        print("\n[-] Configuracion cancelada: el correo destinatario no puede estar vacio.")
        return

    try:
        with open(CREDENTIALS_FILE, "w", encoding="utf-8") as fh:
            fh.write(f"ALERT_EMAIL={sender}\n")
            fh.write(f"ALERT_PASSWORD={password}\n")
            fh.write(f"ALERT_TO={receiver}\n")
        _set_email_enabled(True)
    except Exception as error:
        print(f"\n[-] No se pudo guardar la configuracion: {error}")
        return

    print("\n[+] Alertas por correo configuradas y habilitadas.")
    print(f"    Credenciales guardadas en: {CREDENTIALS_FILE}")
    print("    Las alertas se enviaran la proxima vez que inicie el monitoreo")
    print("    de integridad.")
