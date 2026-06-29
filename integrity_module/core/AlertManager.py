import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import os
from dotenv import load_dotenv
import threading
from toolkitTCU.integrity_module.utils.LoadConfig import ConfigLoader, MODULE_DIR

class AlertManager:

    def __init__(self, load_config: ConfigLoader):
        load_dotenv(os.path.join(MODULE_DIR, "credentials.env"), override=True)
        self.sender_email = os.getenv("ALERT_EMAIL")
        self.receiver_email = os.getenv("ALERT_TO")
        self.password = os.getenv("ALERT_PASSWORD")
        self.email_enabled = load_config.load_config().get("alerts", {}).get("email_enabled", False)

    def send_alert(self, level, subject, message):
        if self.email_enabled:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            body = f"{message}\n\nTimestamp: {timestamp}"
            thread = threading.Thread(target=self.send_email, args=(level, subject, body), daemon=True)
            thread.start()

    def send_email(self, level, subject, message):
        if not (self.sender_email and self.password and self.receiver_email):
            print("[-] Alerta por correo omitida: faltan credenciales (ALERT_EMAIL/ALERT_PASSWORD/ALERT_TO)")
            return
        try:
            subject = f"[{level}] {subject}"
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.ehlo()
            server.starttls()
            server.login(self.sender_email, self.password)

            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = self.receiver_email
            msg['Subject'] = subject
            body = message
            msg.attach(MIMEText(body, "plain"))
            text = msg.as_string()

            server.sendmail(self.sender_email, self.receiver_email, text)
            server.quit()
            print(f"\n[+] Se ha enviado una alerta al correo {self.receiver_email}\n")
        except Exception as e:
            print(f"Error al enviar correo de alerta: {e}")
