"""
Detector de Archivos Expuestos.

Cubre las Actividades 2.8 a 2.10 del proyecto:
    2.8: Cargar y gestionar wordlist de rutas sensibles comunes
    2.9: Mecanismo de peticiones HTTP (GET/HEAD) para verificar existencia
    2.10: Logica para manejar redirecciones, codigos de estado y evitar falsos positivos
"""

import time
import os
import hashlib
import requests
from urllib.parse import urljoin, urlparse
from requests.exceptions import RequestException, Timeout

from utils.model import (
    create_finding,
    create_scanner_result,
    calculate_score,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFO,
    STATUS_COMPLETED,
    STATUS_FAILED,
)
from utils.logger import get_logger


SCANNER_NAME = "Detector de Archivos Expuestos"
OWASP_CATEGORY = "OWASP A01:2021 - Broken Access Control"

# Mapeo de severidad por tipo de archivo expuesto
SEVERITY_BY_PATH = {
    # CRITICAL: archivos con credenciales o datos completos
    "CRITICAL": [".env", "wp-config", "config.php.bak", "configuration.php.bak",
                 "backup.sql", "dump.sql", "database.sql", "db_backup.sql",
                 "mysql.sql", "appsettings.json", "local.settings.json",
                 "credentials.txt", "passwords.txt"],
    # HIGH: codigo fuente, repositorios, backups parciales
    "HIGH": [".git/", ".svn/", "backup.zip", "backup.tar.gz", "www.zip",
             "www.tar.gz", "site.zip", "public_html.zip", ".hg/", ".bzr/"],
    # MEDIUM: archivos de log, configuracion menos sensible
    "MEDIUM": [".log", "phpinfo.php", "info.php", "test.php", "adminer.php",
               "docker-compose.yml", "Dockerfile", "deploy.sh", "deploy.php",
               "install.php", "setup.php", "installer.php"],
    # LOW: archivos de IDE, metadatos, documentacion
    "LOW": [".DS_Store", "Thumbs.db", ".vscode/", ".idea/", ".gitignore",
            "README.md.bak", "CHANGELOG.txt", "TODO.txt", "notes.txt",
            ".dockerignore", ".travis.yml", ".gitlab-ci.yml"],
}


# Carga la wordlist desde archivo
def load_wordlist(wordlist_path):
    if not os.path.isfile(wordlist_path):
        return []

    paths = []
    with open(wordlist_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                paths.append(line)
    return paths

# Determina la severidad de un archivo expuesto segun su tipo
def determine_severity(path):
    for severity, patterns in SEVERITY_BY_PATH.items():
        for pattern in patterns:
            if pattern in path:
                return severity
    return SEVERITY_INFO

# Obtiene la huella de una pagina 404 para detectar falsos positivos
def get_404_fingerprint(base_url, timeout=10):
 
    nonexistent_path = "/__no_existe_" + hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
    test_url = urljoin(base_url, nonexistent_path)

    try:
        response = requests.get(
            test_url,
            timeout=timeout,
            allow_redirects=False,
            headers={"User-Agent": "ONG-Security-Tool"},
            verify=False,
        )
        content = response.content[:2048]  # primeros 2KB son suficientes
        content_hash = hashlib.md5(content).hexdigest()
        return response.status_code, len(response.content), content_hash
    except Exception:
        return None, None, None

# Verifica si una ruta existe y no es un falso positivo comparando con la huella 404
def check_path(base_url, path, fingerprint_404, timeout=10):
    url = urljoin(base_url, path)

    try:
        # Primer intenta con HEAD
        response = requests.head(
            url,
            timeout=timeout,
            allow_redirects=False,
            headers={"User-Agent": "ONG-Security-Tool"},
            verify=False,
        )

        # Si HEAD no es soportado o no da info util, probar GET
        if response.status_code in (405, 501) or response.status_code == 200:
            response = requests.get(
                url,
                timeout=timeout,
                allow_redirects=False,
                headers={"User-Agent": "ONG-Security-Tool"},
                verify=False,
            )

        status_code = response.status_code
        content_type = response.headers.get("Content-Type", "")
        size = int(response.headers.get("Content-Length", len(response.content)))

        # Manejo de codigos de estado 
        if status_code == 200:
            # Verificar contra la huella 404 para descartar paginas de error genericas
            if fingerprint_404[0] == 200 and fingerprint_404[1] == size:
                content = response.content[:2048] if response.content else b""
                current_hash = hashlib.md5(content).hexdigest()
                if current_hash == fingerprint_404[2]:
                    return None  # Es la misma pagina de error generica

            return {
                "exists": True,
                "status_code": status_code,
                "size": size,
                "url": url,
                "content_type": content_type,
            }

        # 401/403: existe pero requiere autenticacion
        if status_code in (401, 403):
            return {
                "exists": True,
                "status_code": status_code,
                "size": size,
                "url": url,
                "content_type": content_type,
                "protected": True,
            }

        # Redirecciones (301, 302, 307, 308) pueden indicar que el recurso existe pero esta movido o protegido
        if status_code in (301, 302, 307, 308):
            return None

        return None

    except (Timeout, RequestException):
        return None

# Construye un hallazgo detallado para un archivo expuesto, ajustando la severidad si esta protegido
def build_finding_for_file(info, path):
    severity = determine_severity(path)
    protected = info.get("protected", False)

    # Si esta protegido (401/403), bajar la severidad un nivel
    if protected:
        downgrade = {
            SEVERITY_CRITICAL: SEVERITY_HIGH,
            SEVERITY_HIGH: SEVERITY_MEDIUM,
            SEVERITY_MEDIUM: SEVERITY_LOW,
            SEVERITY_LOW: SEVERITY_INFO,
        }
        severity = downgrade.get(severity, severity)

    title = f"Ruta sensible accesible: {path}"
    if protected:
        title = f"Ruta sensible detectada (acceso protegido): {path}"

    accessible_description = (
        f"Se detecto en su sitio el archivo o directorio '{path}'. Este tipo de archivo "
        f"suele contener informacion interna que no deberia estar visible publicamente."
    )

    if ".env" in path or "config" in path.lower():
        accessible_description = (
            f"Su sitio expone publicamente el archivo de configuracion '{path}'. Estos "
            f"archivos suelen contener contrasenas, claves de acceso a bases de datos y "
            f"credenciales de servicios externos. Cualquier persona con la URL puede leerlo."
        )
    elif ".git" in path or ".svn" in path:
        accessible_description = (
            f"Su sitio expone parte del repositorio de codigo fuente ('{path}'). Esto "
            f"permite a un atacante reconstruir el codigo de su sitio e identificar fallos "
            f"de seguridad para explotarlos."
        )
    elif "backup" in path or ".sql" in path or ".zip" in path or ".tar" in path:
        accessible_description = (
            f"Se detecto un archivo de respaldo accesible publicamente ('{path}'). Estos "
            f"archivos suelen contener una copia completa de la base de datos o del sitio, "
            f"con todos los datos de usuarios, contrasenas y contenido."
        )

    recommendation = (
        f"1. Eliminar inmediatamente el archivo '{path}' del directorio publico del sitio.\n"
        f"2. Si contiene credenciales, rotar todas las que esten en el archivo.\n"
        f"3. Configurar el servidor web para denegar el acceso a archivos de configuracion "
        f"y archivos ocultos (que inician con punto)."
    )

    return create_finding(
        finding_id=f"WEB-FE-{abs(hash(path)) % 1000:03d}",
        title=title,
        severity=severity,
        owasp_category=OWASP_CATEGORY,
        accessible_description=accessible_description,
        technical_description=(
            f"URL detectada: {info['url']}\n"
            f"Codigo HTTP: {info['status_code']}\n"
            f"Tamano respuesta: {info['size']} bytes\n"
            f"Content-Type: {info['content_type']}"
        ),
        recommendation=recommendation,
        evidence={
            "url": info["url"],
            "http_status": info["status_code"],
            "size_bytes": info["size"],
            "content_type": info["content_type"],
            "protected": protected,
        },
    )

# Funcion principal del escaner de archivos expuestos
def run(url, wordlist_path=None, timeout=10, max_paths=None):
    log = get_logger()
    log.info(f"[Archivos Expuestos] Iniciando analisis de {url}")

    # Suprimir warnings de SSL no verificado para sitios autofirmados
    requests.packages.urllib3.disable_warnings()

    result = create_scanner_result(SCANNER_NAME)
    start = time.time()

    # Wordlist por defecto
    if wordlist_path is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        wordlist_path = os.path.join(base_dir, "wordlists", "sensitive_paths.txt")

    paths = load_wordlist(wordlist_path)
    if not paths:
        result["status"] = STATUS_FAILED
        result["error_message"] = f"No se pudo cargar la wordlist desde {wordlist_path}"
        result["duration_seconds"] = round(time.time() - start, 2)
        return result

    if max_paths:
        paths = paths[:max_paths]

    log.info(f"[Archivos Expuestos] Wordlist cargada: {len(paths)} rutas a verificar")

    # Asegurar que la URL termine en /
    if not url.endswith("/"):
        base_url = url + "/"
    else:
        base_url = url

    # Obtener huella de pagina inexistente para detectar falsos positivos
    log.info(f"[Archivos Expuestos] Calculando huella de pagina 404")
    fingerprint_404 = get_404_fingerprint(base_url, timeout)

    # Verificar cada ruta
    found = 0
    for i, path in enumerate(paths, 1):
        if i % 20 == 0:
            log.info(f"[Archivos Expuestos] Progreso: {i}/{len(paths)}")

        info = check_path(base_url, path, fingerprint_404, timeout)
        if info and info.get("exists"):
            finding = build_finding_for_file(info, path)
            result["findings"].append(finding)
            found += 1
            log.warning(f"[Archivos Expuestos] DETECTADO: {path} ({info['status_code']})")

    result["status"] = STATUS_COMPLETED
    result["score"] = calculate_score(result["findings"])
    result["duration_seconds"] = round(time.time() - start, 2)

    log.info(
        f"[Archivos Expuestos] Finalizado - {found} archivos detectados - "
        f"puntaje {result['score']}/100"
    )
    return result
