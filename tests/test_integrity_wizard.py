
import json
from unittest.mock import patch

from toolkitTCU.integrity_module.utils.SetupWizard import SetupWizard

def _base_config():
    return {
        "watch": [{"paths": ["x"], "recursive": True}],
        "backup": {"directory": "${MODULE_DIR}/snapshots", "interval_seconds": 10},
        "scan": {"interval_seconds": 10},
        "alerts": {"email_enabled": False},
        "default_baseline": {"paths": ["x"]},
        "default_hashing_algorithm": "sha256",
    }

def test_wizard_escribe_config_y_marcador(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps(_base_config()))
    watched = tmp_path / "w"
    watched.mkdir()

    w = SetupWizard(config_path=str(p))
    assert w.is_configured() is False

    answers = iter([str(watched), "s", "2", "15", "n"])
    with patch("builtins.input", lambda *a: next(answers)):
        w.run()

    data = json.loads(p.read_text())
    assert data["watch"][0]["paths"] == [str(watched)]
    assert data["default_baseline"]["paths"] == [str(watched)]
    assert data["default_hashing_algorithm"] == "sha512"
    assert data["scan"]["interval_seconds"] == 15
    assert data["alerts"]["email_enabled"] is False
    assert "${MODULE_DIR}" in data["backup"]["directory"]
    assert w.is_configured() is True

def test_maybe_run_no_corre_si_ya_configurado(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps(_base_config()))
    w = SetupWizard(config_path=str(p))
    open(w.marker_path, "w").write("ya\n")
    w.maybe_run()
    assert w.is_configured() is True
