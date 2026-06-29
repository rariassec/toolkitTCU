
import os

def _detect(fim, path):
    flag, _ = fim.fic.detect_any_hash_change(path, False, False, False, False, [""], None)
    return flag

def test_archivo_sin_cambios_se_verifica(fim, tmp_path):
    f = tmp_path / "watched" / "doc.txt"
    f.write_text("original")
    assert fim.hs.store_hash(str(f), "sha256") is True
    assert _detect(fim, str(f)) == "VERIFIED"

def test_archivo_modificado_se_detecta(fim, tmp_path):
    f = tmp_path / "watched" / "doc.txt"
    f.write_text("original")
    fim.hs.store_hash(str(f), "sha256")
    f.write_text("contenido modificado distinto")
    assert _detect(fim, str(f)) == "MODIFIED"

def test_modificacion_contenido_con_guardado_atomico_se_detecta(fim, tmp_path):
    f = tmp_path / "watched" / "doc.txt"
    f.write_text("original")
    fim.hs.store_hash(str(f), "sha256")
    inode_viejo = os.stat(str(f)).st_ino
    nuevo = tmp_path / "watched" / "doc.txt.tmp"
    nuevo.write_text("contenido alterado por guardado atomico")
    os.replace(str(nuevo), str(f))
    assert os.stat(str(f)).st_ino != inode_viejo
    assert _detect(fim, str(f)) == "MODIFIED"

def test_archivo_eliminado_se_detecta(fim, tmp_path):
    f = tmp_path / "watched" / "doc.txt"
    f.write_text("original")
    fim.hs.store_hash(str(f), "sha256")
    os.remove(str(f))
    assert _detect(fim, str(f)) == "DELETED"

def test_multiples_eventos_simultaneos(fim, tmp_path):
    archivos = []
    for i in range(3):
        f = tmp_path / "watched" / f"f{i}.txt"
        f.write_text(f"contenido {i}")
        fim.hs.store_hash(str(f), "sha256")
        archivos.append(f)
    for f in archivos:
        f.write_text("modificado " + f.name)
    flags = [_detect(fim, str(f)) for f in archivos]
    assert flags == ["MODIFIED", "MODIFIED", "MODIFIED"]

def _modified_entries(changes):
    return [c for c in changes.values() if c["event_type"] == "MODIFIED"]

def test_carpeta_con_cambios_se_detecta(fim, tmp_path):
    d = tmp_path / "watched" / "carpeta"
    d.mkdir(parents=True)
    a = d / "a.conf"
    b = d / "b.txt"
    a.write_text("uno")
    b.write_text("dos")
    fim.hs.store_hash(str(d), "sha256")
    a.write_text("uno cambiado")
    b.write_text("dos cambiado")
    changes, _ = fim.fic.detect_any_hash_change(str(d), True, True, True, False, [""], None)
    assert isinstance(changes, dict)
    assert len(_modified_entries(changes)) == 2

def test_filtro_extensiones_con_punto_funciona(fim, tmp_path):
    d = tmp_path / "watched" / "carpeta2"
    d.mkdir(parents=True)
    a = d / "a.conf"
    b = d / "b.txt"
    a.write_text("uno")
    b.write_text("dos")
    fim.hs.store_hash(str(d), "sha256")
    a.write_text("uno cambiado")
    b.write_text("dos cambiado")
    changes, _ = fim.fic.detect_any_hash_change(str(d), True, True, True, False, [".conf"], None)
    modificados = _modified_entries(changes)
    assert len(modificados) == 1
    assert modificados[0]["file_path"].endswith("a.conf")

def test_evento_de_creacion_se_registra_en_bd(fim, tmp_path):
    f = tmp_path / "watched" / "nuevo.txt"
    f.write_text("x")
    fim.hs.store_hash(str(f), "sha256")
    fim.em.generate_creation_event(str(f), "CREATED")
    eventos = fim.db.get_events_with_severity()
    assert any(e["event_type"] == "CREATED" for e in eventos)
