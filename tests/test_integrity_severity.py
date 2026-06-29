
def test_severidad_critica_por_ruta_sensible(fim):
    assert fim.em.get_severity("/etc/passwd", "MODIFIED") == "CRITICAL"

def test_severidad_por_defecto_para_ruta_comun(fim):
    assert fim.em.get_severity("/home/usuario/archivo.txt", "MODIFIED") == "MEDIUM"

def test_severidad_creacion(fim):
    assert fim.em.get_severity("/cualquier/ruta", "CREATED") == "LOW"

def test_evento_verified_no_tiene_severidad(fim):
    assert fim.em.get_severity("/x", "VERIFIED") is None

def test_event_type_se_normaliza_a_mayusculas(fim):
    assert fim.em.get_severity("/etc/passwd", "modified") == "CRITICAL"

def test_severidad_coincide_subrutas_con_patron_sin_comodin(fim):
    fim.em.loaded_config["severity_levels"] = {"MODIFIED": {"CRITICAL": ["/etc"]}}
    assert fim.em.get_severity("/etc/ssh/sshd_config", "MODIFIED") == "CRITICAL"
    assert fim.em.get_severity("/etc", "MODIFIED") == "CRITICAL"
