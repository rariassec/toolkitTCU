
import os

def _store(db_manager, tmp_path, name="a.txt", content="x"):
    f = tmp_path / name
    f.write_text(content)
    inode, device = db_manager.file_handler.extract_file_info(str(f))
    return f, inode, device

def test_insert_y_consult_hash(db_manager, tmp_path):
    f, inode, device = _store(db_manager, tmp_path)
    assert db_manager.insert_hash(inode, "hash123", device, str(f)) is True
    info = db_manager.consult_all_file_info_by_path(str(f))
    assert info["hash"] == "hash123"

def test_algorithm_id_es_entero_con_algoritmo_por_defecto(db_manager, tmp_path):
    f, inode, device = _store(db_manager, tmp_path)
    db_manager.insert_hash(inode, "h", device, str(f))
    info = db_manager.consult_all_file_info_by_path(str(f))
    assert isinstance(info["algorithm_id"], int)

def test_consult_inode_de_ruta_inexistente_devuelve_none(db_manager):
    assert db_manager.consult_inode_and_device_by_path("/no/existe.txt") is None

def test_obtain_full_info_de_ruta_inexistente_devuelve_none(db_manager):
    assert db_manager.obtain_full_info_by_path("/no/existe.txt") is None

def test_eventos_con_severidad(db_manager, tmp_path):
    f, inode, device = _store(db_manager, tmp_path)
    db_manager.insert_creation_event(inode, device, "h", str(f), "MEDIUM")
    eventos = db_manager.get_events_with_severity()
    assert len(eventos) == 1
    assert eventos[0]["event_type"] == "CREATED"
    assert eventos[0]["severity"] == "MEDIUM"
