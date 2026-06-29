
import json
from unittest.mock import patch

from toolkitTCU.integrity_module.utils import AlertConfig

def test_configura_credenciales_y_habilita(tmp_path, monkeypatch):
    creds = tmp_path / "credentials.env"
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"alerts": {"email_enabled": False}}))
    monkeypatch.setattr(AlertConfig, "CREDENTIALS_FILE", str(creds))
    monkeypatch.setattr(AlertConfig, "DEFAULT_CONFIG_FILE", str(cfg))

    respuestas = iter(["emisor@gmail.com", "destino@gmail.com"])
    with patch("builtins.input", lambda *a: next(respuestas)),         patch("getpass.getpass", lambda *a: "clave-app"):
        AlertConfig.configure_email_alerts()

    contenido = creds.read_text()
    assert "ALERT_EMAIL=emisor@gmail.com" in contenido
    assert "ALERT_PASSWORD=clave-app" in contenido
    assert "ALERT_TO=destino@gmail.com" in contenido
    assert json.loads(cfg.read_text())["alerts"]["email_enabled"] is True

def test_cancela_si_emisor_vacio(tmp_path, monkeypatch):
    creds = tmp_path / "credentials.env"
    monkeypatch.setattr(AlertConfig, "CREDENTIALS_FILE", str(creds))

    with patch("builtins.input", lambda *a: ""),         patch("getpass.getpass", lambda *a: "x"):
        AlertConfig.configure_email_alerts()

    assert not creds.exists()
