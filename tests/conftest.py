
import json
import os
import tempfile

import pytest

os.environ.setdefault("FIM_DB_PATH", os.path.join(tempfile.mkdtemp(), "safety.db"))

def _build_config(base):
    watched = os.path.join(base, "watched")
    os.makedirs(watched, exist_ok=True)
    return {
        "watch": [{"paths": [watched], "recursive": True}],
        "include_patterns": [".*"],
        "exclude_patterns": [],
        "default_hashing_algorithm": "sha256",
        "backup": {"directory": os.path.join(base, "snapshots"), "interval_seconds": 10},
        "scan": {"interval_seconds": 10},
        "alerts": {"email_enabled": False, "desktop_notifications": False},
        "logging": {"directory": os.path.join(base, "logs")},
        "reports": {
            "individual": os.path.join(base, "reports"),
            "general": os.path.join(base, "reports"),
        },
        "default_baseline": {"paths": [watched]},
        "severity_levels": {
            "MODIFIED": {"CRITICAL": ["/etc/*"], "MEDIUM": ["*"]},
            "DELETED": {"HIGH": ["/etc/*"], "MEDIUM": ["*"]},
            "CREATED": {"LOW": ["*"]},
        },
        "default_severity": "MEDIUM",
    }

@pytest.fixture
def watched_dir(tmp_path):
    d = tmp_path / "watched"
    d.mkdir(exist_ok=True)
    return d

@pytest.fixture
def config_loader(tmp_path):
    from toolkitTCU.integrity_module.utils.LoadConfig import ConfigLoader
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(json.dumps(_build_config(str(tmp_path))))
    return ConfigLoader(str(cfg_path))

@pytest.fixture
def db_manager(tmp_path, monkeypatch, config_loader):
    db_path = str(tmp_path / "hashes.db")
    import sys
    import toolkitTCU.integrity_module.core.DatabaseManager
    dbmod = sys.modules["toolkitTCU.integrity_module.core.DatabaseManager"]
    monkeypatch.setattr(dbmod, "DB_PATH", db_path)
    dm = dbmod.DatabaseManager(config_loader)
    dm.set_DB()
    return dm

@pytest.fixture
def fim(db_manager, config_loader):
    from types import SimpleNamespace
    from toolkitTCU.integrity_module.core.BackupFiles import BackupFiles
    from toolkitTCU.integrity_module.core.HashStorage import HashStorage
    from toolkitTCU.integrity_module.events.EventManager import EventManager
    from toolkitTCU.integrity_module.core.FileIntegrityChecker import FileIntegrityChecker

    log = db_manager.log
    fh = db_manager.file_handler
    backup = BackupFiles(db_manager, fh, log, config_loader)
    hs = HashStorage(db_manager, fh, log, backup, config_loader)
    em = EventManager(db_manager, hs, fh, log, config_loader)
    fic = FileIntegrityChecker(hs, fh, db_manager, log, config_loader)
    return SimpleNamespace(db=db_manager, backup=backup, hs=hs, em=em, fic=fic, fh=fh)
