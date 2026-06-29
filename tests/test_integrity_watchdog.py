import os
from types import SimpleNamespace

from watchdog.events import FileCreatedEvent, FileDeletedEvent, FileModifiedEvent, FileMovedEvent

class _Alert:
    def __init__(self):
        self.sent = []

    def send_alert(self, level, subject, message):
        self.sent.append((level, subject, message))

def _make_handler(fim, alert):
    from toolkitTCU.integrity_module.events.WatchdogEventHandler import EventHandler
    path_tracker = SimpleNamespace(search_file_in_disk=lambda inodes: {})
    return EventHandler(fim.em, fim.fic, fim.hs, fim.backup, fim.db,
                        path_tracker, fim.db.log, alert)

def test_modificacion_in_place_genera_alerta(fim, tmp_path):
    alert = _Alert()
    handler = _make_handler(fim, alert)
    f = tmp_path / "watched" / "a.txt"
    f.write_text("original")
    fim.hs.store_hash(str(f), "sha256")
    f.write_text("contenido alterado distinto")
    handler.on_modified(FileModifiedEvent(str(f)))
    eventos = fim.db.get_events_with_severity()
    assert any(e["event_type"] == "MODIFIED" for e in eventos)
    assert alert.sent

def test_modificacion_por_renombrado_se_detecta(fim, tmp_path):
    alert = _Alert()
    handler = _make_handler(fim, alert)
    f = tmp_path / "watched" / "b.txt"
    f.write_text("v1")
    fim.hs.store_hash(str(f), "sha256")
    old_inode = os.stat(str(f)).st_ino
    nuevo = tmp_path / "watched" / "b.txt.new"
    nuevo.write_text("v2 modificado por un atacante")
    os.replace(str(nuevo), str(f))
    assert os.stat(str(f)).st_ino != old_inode
    handler.on_moved(FileMovedEvent(str(nuevo), str(f)))
    eventos = fim.db.get_events_with_severity()
    assert any(e["event_type"] == "MODIFIED" and e["file_path"] == str(f) for e in eventos)
    assert alert.sent

def test_creacion_de_archivo_genera_alerta(fim, tmp_path):
    alert = _Alert()
    handler = _make_handler(fim, alert)
    nuevo = tmp_path / "watched" / "nuevo.txt"
    nuevo.write_text("contenido")
    handler.on_created(FileCreatedEvent(str(nuevo)))
    eventos = fim.db.get_events_with_severity()
    assert any(e["event_type"] == "CREATED" for e in eventos)
    assert any(s == "Archivo Creado" for _, s, _ in alert.sent)

def test_renombrar_archivo_genera_alerta_y_actualiza_ruta(fim, tmp_path):
    alert = _Alert()
    handler = _make_handler(fim, alert)
    viejo = tmp_path / "watched" / "viejo.txt"
    viejo.write_text("contenido")
    fim.hs.store_hash(str(viejo), "sha256")
    nuevo = tmp_path / "watched" / "nuevo_nombre.txt"
    os.rename(str(viejo), str(nuevo))
    handler.on_moved(FileMovedEvent(str(viejo), str(nuevo)))
    assert any(s == "Archivo Renombrado" for _, s, _ in alert.sent)
    rutas = [p for p in fim.db.consult_all_file_paths()]
    assert str(nuevo) in rutas
    assert str(viejo) not in rutas

def test_monitoreo_no_sobreescribe_huella_base(fim, tmp_path):
    alert = _Alert()
    handler = _make_handler(fim, alert)
    f = tmp_path / "watched" / "doc.txt"
    f.write_text("original")
    fim.hs.store_hash(str(f), "sha256")
    base = fim.db.consult_all_file_info_by_path(str(f))["hash"]
    f.write_text("contenido modificado distinto")
    handler.on_modified(FileModifiedEvent(str(f)))
    assert alert.sent
    assert fim.db.consult_all_file_info_by_path(str(f))["hash"] == base
    flag, _ = fim.fic.detect_any_hash_change(str(f), True, True, True, False, [""], None)
    assert flag == "MODIFIED"

def test_archivos_swap_se_ignoran(fim, tmp_path):
    alert = _Alert()
    handler = _make_handler(fim, alert)
    swp = tmp_path / "watched" / ".x.txt.swp"
    swp.write_text("swap")
    before = len(fim.db.get_events_with_severity())
    handler.dispatch(FileCreatedEvent(str(swp)))
    handler.dispatch(FileDeletedEvent(str(swp)))
    after = len(fim.db.get_events_with_severity())
    assert before == after
    assert not alert.sent
