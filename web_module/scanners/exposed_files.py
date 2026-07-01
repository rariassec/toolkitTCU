
import time
import os
import hashlib
import requests
from urllib.parse import urljoin
from requests.exceptions import RequestException, Timeout

from toolkitTCU.web_module.utils.model import (
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
from toolkitTCU.web_module.utils.logger import get_logger

SCANNER_NAME = "Detector de Archivos Expuestos"
OWASP_CATEGORY = "OWASP A01:2021 - Broken Access Control"

SEVERITY_BY_PATH = {
    "CRITICAL": [".env", "wp-config", "config.php.bak", "configuration.php.bak",
                 "backup.sql", "dump.sql", "database.sql", "db_backup.sql",
                 "mysql.sql", "appsettings.json", "local.settings.json",
                 "credentials.txt", "passwords.txt"],
    "HIGH": [".git/", ".svn/", "backup.zip", "backup.tar.gz", "www.zip",
             "www.tar.gz", "site.zip", "public_html.zip", ".hg/", ".bzr/"],
    "MEDIUM": [".log", "phpinfo.php", "info.php", "test.php", "adminer.php",
               "docker-compose.yml", "Dockerfile", "deploy.sh", "deploy.php",
               "install.php", "setup.php", "installer.php"],
    "LOW": [".DS_Store", "Thumbs.db", ".vscode/", ".idea/", ".gitignore",
            "README.md.bak", "CHANGELOG.txt", "TODO.txt", "notes.txt",
            ".dockerignore", ".travis.yml", ".gitlab-ci.yml"],
}

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

def determine_severity(path):
    for severity, patterns in SEVERITY_BY_PATH.items():
        for pattern in patterns:
            if pattern in path:
                return severity
    return SEVERITY_INFO

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
        content = response.content[:2048]
        content_hash = hashlib.md5(content).hexdigest()
        return response.status_code, len(response.content), content_hash
    except Exception:
        return None, None, None

def check_path(base_url, path, fingerprint_404, timeout=10):
    url = urljoin(base_url, path)

    try:
        response = requests.head(
            url,
            timeout=timeout,
            allow_redirects=False,
            headers={"User-Agent": "ONG-Security-Tool"},
            verify=False,
        )

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

        if status_code == 200:
            if fingerprint_404[0] == 200 and fingerprint_404[1] == size:
                content = response.content[:2048] if response.content else b""
                current_hash = hashlib.md5(content).hexdigest()
                if current_hash == fingerprint_404[2]:
                    return None

            return {
                "exists": True,
                "status_code": status_code,
                "size": size,
                "url": url,
                "content_type": content_type,
            }

        if status_code in (401, 403):
            return {
                "exists": True,
                "status_code": status_code,
                "size": size,
                "url": url,
                "content_type": content_type,
                "protected": True,
            }

        if status_code in (301, 302, 307, 308):
            return None

        return None

    except (Timeout, RequestException):
        return None

def build_finding_for_file(info, path):
    severity = determine_severity(path)
    protected = info.get("protected", False)

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
        f"Se detectó en su sitio el archivo o directorio '{path}'. Este tipo de archivo "
        f"suele contener información interna que no debería estar visible públicamente."
    )

    if ".env" in path or "config" in path.lower():
        accessible_description = (
            f"Su sitio expone públicamente el archivo de configuración '{path}'. Estos "
            f"archivos suelen contener contraseñas, claves de acceso a bases de datos y "
            f"credenciales de servicios externos. Cualquier persona con la URL puede leerlo."
        )
    elif ".git" in path or ".svn" in path:
        accessible_description = (
            f"Su sitio expone parte del repositorio de código fuente ('{path}'). Esto "
            f"permite a un atacante reconstruir el código de su sitio e identificar fallos "
            f"de seguridad para explotarlos."
        )
    elif "backup" in path or ".sql" in path or ".zip" in path or ".tar" in path:
        accessible_description = (
            f"Se detectó un archivo de respaldo accesible públicamente ('{path}'). Estos "
            f"archivos suelen contener una copia completa de la base de datos o del sitio, "
            f"con todos los datos de usuarios, contraseñas y contenido."
        )

    recommendation = (
        f"1. Eliminar inmediatamente el archivo '{path}' del directorio público del sitio.\n"
        f"2. Si contiene credenciales, rotar todas las que estén en el archivo.\n"
        f"3. Configurar el servidor web para denegar el acceso a archivos de configuración "
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
            f"Código HTTP: {info['status_code']}\n"
            f"Tamaño respuesta: {info['size']} bytes\n"
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

def run(url, wordlist_path=None, timeout=10, max_paths=None):
    log = get_logger()
    log.info(f"[Archivos Expuestos] Iniciando analisis de {url}")

    requests.packages.urllib3.disable_warnings()

    result = create_scanner_result(SCANNER_NAME)
    start = time.time()

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

    if not url.endswith("/"):
        base_url = url + "/"
    else:
        base_url = url

    log.info(f"[Archivos Expuestos] Calculando huella de pagina 404")
    fingerprint_404 = get_404_fingerprint(base_url, timeout)

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
