"""
Funcionalidades Adicionales

Cubre las Actividades 2.13, 2.14 y 2.15 del proyecto:
    2.13: Analisis de cookies (Secure, HttpOnly, SameSite)
    2.14: Verificacion de robots.txt y sitemap.xml
    2.15: Modulo de analisis de tecnologias web (CMS, servidores)
"""

import time
import re
import requests
from urllib.parse import urljoin
from requests.exceptions import RequestException

from utils.model import (
    create_finding,
    create_scanner_result,
    calculate_score,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFO,
    STATUS_COMPLETED,
    STATUS_FAILED,
)
from utils.logger import get_logger


SCANNER_NAME = "Funcionalidades Adicionales"


# Analiza las cookies de la respuesta y genera hallazgos para los atributos de seguridad ausentes (Secure, HttpOnly, SameSite) 
def analyze_cookies(response):
    findings = []
    set_cookies = response.headers.get("Set-Cookie")

    if not set_cookies and not response.cookies:
        return findings

    # Procesa cada cookie individualmente
    raw_cookies = []
    if "Set-Cookie" in response.headers:
        
        # Algunos servidores envian multiples Set-Cookie en un solo header
        try:
            raw = response.raw.headers.get_all("Set-Cookie")
            raw_cookies.extend(raw or [])
        except Exception:
            raw_cookies.append(set_cookies)

    if not raw_cookies and response.cookies:
        for cookie in response.cookies:
            raw_cookies.append(f"{cookie.name}={cookie.value}; "
                               f"{'Secure' if cookie.secure else ''}; "
                               f"{'HttpOnly' if cookie.has_nonstandard_attr('HttpOnly') else ''}")

    analyzed_cookies = []
    for cookie_str in raw_cookies:
        cookie_lower = cookie_str.lower()
        name = cookie_str.split("=")[0].strip()

        analysis = {
            "name": name,
            "secure": "secure" in cookie_lower,
            "httponly": "httponly" in cookie_lower,
            "samesite": None,
        }

        samesite_match = re.search(r"samesite=(\w+)", cookie_lower)
        if samesite_match:
            analysis["samesite"] = samesite_match.group(1)

        analyzed_cookies.append(analysis)

    # Generar hallazgos
    cookies_no_secure = [c["name"] for c in analyzed_cookies if not c["secure"]]
    cookies_no_httponly = [c["name"] for c in analyzed_cookies if not c["httponly"]]
    cookies_no_samesite = [c["name"] for c in analyzed_cookies if not c["samesite"]]

    if cookies_no_secure:
        findings.append(create_finding(
            finding_id="WEB-AD-001",
            title=f"Cookies sin atributo Secure ({len(cookies_no_secure)})",
            severity=SEVERITY_MEDIUM,
            owasp_category="OWASP A05:2021 - Security Misconfiguration",
            accessible_description=(
                "Algunas cookies de su sitio no tienen el atributo Secure activado. Esto "
                "significa que pueden ser enviadas por conexiones no cifradas y ser "
                "interceptadas en redes publicas como WiFi gratuito."
            ),
            technical_description=(
                f"Cookies sin Secure: {', '.join(cookies_no_secure[:5])}"
                + (f" (y {len(cookies_no_secure)-5} mas)" if len(cookies_no_secure) > 5 else "")
            ),
            recommendation=(
                "Configurar todas las cookies con el atributo Secure. En la mayoria de "
                "frameworks esto se configura globalmente."
            ),
            evidence={"cookies": cookies_no_secure[:10]},
        ))

    if cookies_no_httponly:
        findings.append(create_finding(
            finding_id="WEB-AD-002",
            title=f"Cookies sin atributo HttpOnly ({len(cookies_no_httponly)})",
            severity=SEVERITY_MEDIUM,
            owasp_category="OWASP A05:2021 - Security Misconfiguration",
            accessible_description=(
                "Algunas cookies pueden ser leidas por JavaScript en el navegador. Si su "
                "sitio sufre un ataque XSS, las cookies de sesion podrian ser robadas."
            ),
            technical_description=(
                f"Cookies sin HttpOnly: {', '.join(cookies_no_httponly[:5])}"
            ),
            recommendation=(
                "Configurar el atributo HttpOnly en cookies de sesion y autenticacion."
            ),
            evidence={"cookies": cookies_no_httponly[:10]},
        ))

    if cookies_no_samesite:
        findings.append(create_finding(
            finding_id="WEB-AD-003",
            title=f"Cookies sin atributo SameSite ({len(cookies_no_samesite)})",
            severity=SEVERITY_LOW,
            owasp_category="OWASP A05:2021 - Security Misconfiguration",
            accessible_description=(
                "Algunas cookies no especifican como deben comportarse cuando se accede al "
                "sitio desde otro dominio. Esto puede facilitar ataques en los que un usuario "
                "logueado realiza acciones sin saberlo (CSRF)."
            ),
            technical_description=(
                f"Cookies sin SameSite: {', '.join(cookies_no_samesite[:5])}"
            ),
            recommendation=(
                "Configurar SameSite=Lax o SameSite=Strict segun el caso de uso."
            ),
            evidence={"cookies": cookies_no_samesite[:10]},
        ))

    return findings

# Patrones de rutas sensibles que no deberian aparecer en robots.txt o sitemap.xml
SENSITIVE_ROBOTS_PATHS = [
    "admin", "administrator", "wp-admin", "backup", "db", "database",
    "config", "test", "staging", "dev", "private", "internal", "secret",
    "panel", "dashboard", "api/v1", "api/v2",
]

# Descarga y analiza robots.txt buscando rutas sensibles
def analyze_robots(base_url, timeout=10):
    findings = []
    robots_url = urljoin(base_url, "/robots.txt")

    try:
        response = requests.get(
            robots_url,
            timeout=timeout,
            headers={"User-Agent": "ONG-Security-Tool"},
            verify=False,
        )
    except RequestException:
        return findings

    if response.status_code != 200:
        return findings

    content = response.text
    disallow_paths = re.findall(r"(?im)^\s*Disallow:\s*(\S+)", content)

    sensitive_paths_found = []
    for path in disallow_paths:
        path_lower = path.lower()
        for pattern in SENSITIVE_ROBOTS_PATHS:
            if pattern in path_lower:
                sensitive_paths_found.append(path)
                break

    if sensitive_paths_found:
        findings.append(create_finding(
            finding_id="WEB-AD-010",
            title="robots.txt revela rutas sensibles",
            severity=SEVERITY_LOW,
            owasp_category="OWASP A01:2021 - Broken Access Control",
            accessible_description=(
                "El archivo robots.txt de su sitio menciona rutas que parecen administrativas "
                "o internas. Aunque robots.txt indica a los buscadores que no las indexen, "
                "este archivo es publico y un atacante puede leerlo para descubrir secciones "
                "sensibles."
            ),
            technical_description=(
                f"Rutas sensibles encontradas en robots.txt: "
                f"{', '.join(sensitive_paths_found[:5])}"
            ),
            recommendation=(
                "No usar robots.txt para ocultar rutas administrativas. Proteger esas rutas "
                "con autenticacion. Si una ruta es realmente sensible no debe ser accesible "
                "ni siquiera conociendo su URL."
            ),
            evidence={"paths": sensitive_paths_found[:10], "url": robots_url},
        ))

    return findings

# Descarga sitemap.xml y verifica si revela informacion sensible
def analyze_sitemap(base_url, timeout=10):
    findings = []
    sitemap_url = urljoin(base_url, "/sitemap.xml")

    try:
        response = requests.get(
            sitemap_url,
            timeout=timeout,
            headers={"User-Agent": "ONG-Security-Tool"},
            verify=False,
        )
    except RequestException:
        return findings

    if response.status_code != 200:
        return findings

    content = response.text
    urls = re.findall(r"<loc>([^<]+)</loc>", content)

    sensitive_urls = []
    for url in urls:
        url_lower = url.lower()
        for pattern in SENSITIVE_ROBOTS_PATHS:
            if pattern in url_lower:
                sensitive_urls.append(url)
                break

    if sensitive_urls:
        findings.append(create_finding(
            finding_id="WEB-AD-011",
            title="sitemap.xml incluye URLs potencialmente sensibles",
            severity=SEVERITY_LOW,
            owasp_category="OWASP A01:2021 - Broken Access Control",
            accessible_description=(
                "El mapa del sitio (sitemap.xml) lista URLs que parecen corresponder a "
                "secciones internas o administrativas del sitio. Esto facilita a los "
                "atacantes descubrir esas areas."
            ),
            technical_description=(
                f"URLs potencialmente sensibles en sitemap: "
                f"{', '.join(sensitive_urls[:3])}"
            ),
            recommendation=(
                "Excluir URLs administrativas o internas del sitemap.xml. Mantener en el "
                "sitemap solo el contenido publico que se desea indexar."
            ),
            evidence={"urls": sensitive_urls[:10], "total_sitemap_urls": len(urls)},
        ))

    return findings

# Deteccion basica de tecnologias web a partir de headers, meta tags y rutas conocidas
def detect_technologies(base_url, main_response, timeout=10):
    findings = []
    technologies_detected = []

    # Por headers
    server = main_response.headers.get("Server", "")
    x_powered_by = main_response.headers.get("X-Powered-By", "")

    if server:
        technologies_detected.append({"type": "Servidor Web", "name": server})
    if x_powered_by:
        technologies_detected.append({"type": "Backend", "name": x_powered_by})

    # Por contenido HTML
    html_content = ""
    try:
        get_response = requests.get(
            base_url,
            timeout=timeout,
            headers={"User-Agent": "ONG-Security-Tool"},
            verify=False,
        )
        html_content = get_response.text
    except RequestException:
        pass

    # Detectores de CMS
    cms_detected = None
    cms_version = None

    # WordPress
    if re.search(r'/wp-content/|/wp-includes/|wp-json', html_content):
        cms_detected = "WordPress"
        version_match = re.search(r'<meta name="generator" content="WordPress\s+([\d.]+)"', html_content)
        if version_match:
            cms_version = version_match.group(1)

    # Joomla
    elif re.search(r'/components/com_|joomla', html_content, re.IGNORECASE):
        cms_detected = "Joomla"
        version_match = re.search(r'<meta name="generator" content="Joomla!\s*-?\s*([\d.]+)?"', html_content)
        if version_match and version_match.group(1):
            cms_version = version_match.group(1)

    # Drupal
    elif re.search(r'/sites/default/|Drupal\.settings|drupal-settings-json', html_content):
        cms_detected = "Drupal"
        version_match = re.search(r'<meta name="Generator" content="Drupal\s+([\d]+)', html_content)
        if version_match:
            cms_version = version_match.group(1)

    # Generic generator meta
    if not cms_detected:
        gen_match = re.search(r'<meta name="generator" content="([^"]+)"', html_content, re.IGNORECASE)
        if gen_match:
            technologies_detected.append({"type": "Generador", "name": gen_match.group(1)})

    if cms_detected:
        technologies_detected.append({
            "type": "CMS",
            "name": cms_detected,
            "version": cms_version,
        })

        # Si el CMS expone su version, esto es un hallazgo informativo
        if cms_version:
            findings.append(create_finding(
                finding_id="WEB-AD-020",
                title=f"CMS expone su version: {cms_detected} {cms_version}",
                severity=SEVERITY_LOW,
                owasp_category="OWASP A05:2021 - Security Misconfiguration",
                accessible_description=(
                    f"Su sitio anuncia publicamente que usa {cms_detected} version "
                    f"{cms_version}. Esto facilita a un atacante buscar fallos conocidos "
                    f"para esa version especifica."
                ),
                technical_description=(
                    f"Version de {cms_detected} detectada en meta generator: {cms_version}"
                ),
                recommendation=(
                    f"Eliminar el meta tag 'generator' del HTML. En {cms_detected} esto se "
                    f"puede hacer con un plugin de seguridad o agregando codigo al theme."
                ),
                evidence={"cms": cms_detected, "version": cms_version},
            ))
        
    # WordPress tiene un endpoint REST publico que puede revelar usuarios
    if cms_detected == "WordPress":
        try:
            users_response = requests.get(
                urljoin(base_url, "/wp-json/wp/v2/users"),
                timeout=timeout,
                headers={"User-Agent": "ONG-Security-Tool"},
                verify=False,
            )
            if users_response.status_code == 200 and users_response.text.startswith("["):
                findings.append(create_finding(
                    finding_id="WEB-AD-021",
                    title="WordPress expone lista de usuarios via REST API",
                    severity=SEVERITY_MEDIUM,
                    owasp_category="OWASP A01:2021 - Broken Access Control",
                    accessible_description=(
                        "Su sitio WordPress permite a cualquier persona obtener la lista de "
                        "usuarios mediante una direccion publica. Esto facilita ataques "
                        "dirigidos contra cuentas especificas."
                    ),
                    technical_description=(
                        "El endpoint /wp-json/wp/v2/users responde con codigo 200 y un "
                        "arreglo JSON de usuarios."
                    ),
                    recommendation=(
                        "Restringir el acceso al endpoint REST de usuarios mediante un "
                        "plugin de seguridad como Wordfence, iThemes Security o agregando "
                        "una regla a functions.php."
                    ),
                    evidence={"endpoint": "/wp-json/wp/v2/users", "http_status": 200},
                ))
        except RequestException:
            pass

    # Hallazgo informativo con todas las tecnologias detectadas
    if technologies_detected:
        findings.append(create_finding(
            finding_id="WEB-AD-029",
            title="Tecnologias web detectadas",
            severity=SEVERITY_INFO,
            owasp_category="OWASP A05:2021 - Security Misconfiguration",
            accessible_description=(
                "Se identificaron las tecnologias usadas por su sitio. Esta informacion "
                "es util como referencia, pero tambien lo es para un atacante. Mantenga "
                "todas las tecnologias actualizadas a sus ultimas versiones."
            ),
            technical_description=(
                "Tecnologias detectadas a partir de headers, meta tags y rutas conocidas."
            ),
            recommendation=(
                "Mantener todas las tecnologias actualizadas. Suscribirse a alertas de "
                "seguridad para las versiones especificas en uso."
            ),
            evidence={"technologies": technologies_detected},
        ))

    return findings

# Funcion principal
def run(url, timeout=10):
    log = get_logger()
    log.info(f"[Adicionales] Iniciando analisis de {url}")
    requests.packages.urllib3.disable_warnings()

    result = create_scanner_result(SCANNER_NAME)
    start = time.time()

    # Realizar peticion principal una sola vez
    try:
        main_response = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": "ONG-Security-Tool"},
            verify=False,
            allow_redirects=True,
        )
    except RequestException as e:
        result["status"] = STATUS_FAILED
        result["error_message"] = f"No se pudo conectar al sitio: {e}"
        result["duration_seconds"] = round(time.time() - start, 2)
        return result

    # Cookies
    log.info("[Adicionales] Analizando cookies")
    try:
        result["findings"].extend(analyze_cookies(main_response))
    except Exception as e:
        log.warning(f"[Adicionales] Error analizando cookies: {e}")

    # robots.txt y sitemap.xml
    log.info("[Adicionales] Analizando robots.txt")
    try:
        result["findings"].extend(analyze_robots(url, timeout))
    except Exception as e:
        log.warning(f"[Adicionales] Error analizando robots.txt: {e}")

    log.info("[Adicionales] Analizando sitemap.xml")
    try:
        result["findings"].extend(analyze_sitemap(url, timeout))
    except Exception as e:
        log.warning(f"[Adicionales] Error analizando sitemap.xml: {e}")

    # Tecnologias web 
    log.info("[Adicionales] Detectando tecnologias web")
    try:
        result["findings"].extend(detect_technologies(url, main_response, timeout))
    except Exception as e:
        log.warning(f"[Adicionales] Error detectando tecnologias: {e}")

    result["status"] = STATUS_COMPLETED
    result["score"] = calculate_score(result["findings"])
    result["duration_seconds"] = round(time.time() - start, 2)

    log.info(
        f"[Adicionales] Finalizado - {len(result['findings'])} hallazgos - "
        f"puntaje {result['score']}/100"
    )
    return result
