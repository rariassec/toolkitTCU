
import json

from toolkitTCU.integrity_module.utils.LoadConfig import ConfigLoader, MODULE_DIR

def test_expande_module_dir(tmp_path):
    cfg = {"logging": {"directory": "${MODULE_DIR}/logs"}, "lista": ["${MODULE_DIR}/a"]}
    p = tmp_path / "c.json"
    p.write_text(json.dumps(cfg))
    data = ConfigLoader(str(p)).load_config()
    assert data["logging"]["directory"] == MODULE_DIR + "/logs"
    assert data["lista"][0] == MODULE_DIR + "/a"

def test_archivo_inexistente_devuelve_dict_vacio():
    data = ConfigLoader("/ruta/que/no/existe/config.json").load_config()
    assert data == {}

def test_siempre_devuelve_dict(tmp_path):
    p = tmp_path / "lista.json"
    p.write_text(json.dumps([1, 2, 3]))
    assert ConfigLoader(str(p)).load_config() == {}
