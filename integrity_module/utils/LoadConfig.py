import json
import os
import shutil
import traceback

MODULE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEFAULT_CONFIG_FILE = os.path.join(MODULE_DIR, "core", "config", "config.json")

DEFAULT_TEMPLATE_FILE = os.path.join(MODULE_DIR, "core", "config", "config.default.json")

def ensure_config_exists():
    if not os.path.exists(DEFAULT_CONFIG_FILE) and os.path.exists(DEFAULT_TEMPLATE_FILE):
        shutil.copy(DEFAULT_TEMPLATE_FILE, DEFAULT_CONFIG_FILE)

_PORTABLE_DIRS = {
    ("backup", "directory"): "${MODULE_DIR}/snapshots",
    ("logging", "directory"): "${MODULE_DIR}/utils/logs",
    ("reports", "individual"): "${MODULE_DIR}/reports/general",
    ("reports", "general"): "${MODULE_DIR}/reports/general",
}

def bootstrap_config():
    ensure_config_exists()
    try:
        with open(DEFAULT_CONFIG_FILE, "r", encoding="utf-8") as config_file:
            config_data = json.load(config_file)
    except Exception:
        return
    changed = False
    for (section, key), placeholder in _PORTABLE_DIRS.items():
        section_data = config_data.get(section)
        if not isinstance(section_data, dict):
            section_data = {}
            config_data[section] = section_data
        if section_data.get(key) != placeholder:
            section_data[key] = placeholder
            changed = True
    if changed:
        try:
            with open(DEFAULT_CONFIG_FILE, "w", encoding="utf-8") as config_file:
                json.dump(config_data, config_file, indent=4, ensure_ascii=False)
        except Exception:
            pass
    for placeholder in set(_PORTABLE_DIRS.values()):
        try:
            os.makedirs(placeholder.replace("${MODULE_DIR}", MODULE_DIR), exist_ok=True)
        except Exception:
            pass

class ConfigLoader:

    def __init__(self, config_file=DEFAULT_CONFIG_FILE):
        self.config_file = config_file

    def _expand_paths(self, value):
        if isinstance(value, str):
            return value.replace("${MODULE_DIR}", MODULE_DIR)
        if isinstance(value, list):
            return [self._expand_paths(item) for item in value]
        if isinstance(value, dict):
            return {key: self._expand_paths(item) for key, item in value.items()}
        return value

    def load_config(self) -> dict:
        try:
            if self.config_file == DEFAULT_CONFIG_FILE:
                ensure_config_exists()
            with open(self.config_file, 'r') as config_file:
                config_data = json.load(config_file)
            expanded = self._expand_paths(config_data)
            return expanded if isinstance(expanded, dict) else {}
        except Exception as e:
            print(f"Error al cargar archivo de configuracion {self.config_file}: {e}")
            print(traceback.format_exc())
            return {}
