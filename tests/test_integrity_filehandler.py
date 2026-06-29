
import hashlib
import os

from toolkitTCU.integrity_module.utils.FileHandler import FileHandler

def _handler(db_manager):
    return FileHandler(db_manager, db_manager.log)

def test_hash_de_contenido_conocido(db_manager, tmp_path):
    fh = _handler(db_manager)
    f = tmp_path / "a.txt"
    f.write_bytes(b"contenido de prueba")
    esperado = hashlib.sha256(b"contenido de prueba").hexdigest()
    assert fh.calculate_file_hash(str(f), "sha256") == esperado

def test_hash_cambia_al_modificar(db_manager, tmp_path):
    fh = _handler(db_manager)
    f = tmp_path / "a.txt"
    f.write_text("v1")
    h1 = fh.calculate_file_hash(str(f), "sha256")
    f.write_text("v2 distinto")
    h2 = fh.calculate_file_hash(str(f), "sha256")
    assert h1 != h2

def test_omite_archivos_especiales(db_manager, tmp_path):
    fh = _handler(db_manager)
    fifo = tmp_path / "un_fifo"
    os.mkfifo(str(fifo))
    assert fh.calculate_file_hash(str(fifo)) == ""

def test_calculate_file_size_formato(db_manager, tmp_path):
    fh = _handler(db_manager)
    f = tmp_path / "a.txt"
    f.write_bytes(b"x" * 100)
    assert fh.calculate_file_size(str(f)) == "100 B"

def test_extract_file_info_devuelve_inodo_y_device(db_manager, tmp_path):
    fh = _handler(db_manager)
    f = tmp_path / "a.txt"
    f.write_text("x")
    inode, device = fh.extract_file_info(str(f))
    assert inode is not None
    assert device is not None
