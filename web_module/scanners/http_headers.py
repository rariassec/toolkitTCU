"""
Verificador de Headers HTTP

Cubre las Actividades 2.1, 2.2 y 2.3 del proyecto:
    2.1: Obtener headers del sitio web y parsear la respuesta
    2.2: Analizar headers de seguridad (HSTS, CSP, X-Frame-Options, etc.)
    2.3: Sistema de puntuacion y recomendaciones

Headers evaluados (segun la priorizacion de la Actividad 1.2):
    Strict-Transport-Security (HSTS)
    Content-Security-Policy (CSP)
    X-Frame-Options
    X-Content-Type-Options
    Referrer-Policy
    Permissions-Policy
"""

import time
import requests
from requests.exceptions import RequestException, Timeout, ConnectionError as ReqConnectionError

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


SCANNER_NAME = "Verificador de Headers HTTP"
OWASP_CATEGORY = "OWASP A05:2021 - Security Misconfiguration"


# Realiza una peticion HEAD al sitio y retorna los headers
def fetch_headers(url, timeout=15, verify_ssl=True):

    request_headers = {
        "User-Agent": "ONG-Security-Tool (Modulo de Analisis Web)"
    }

    try:
        response = requests.head(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=verify_ssl,
            headers=request_headers,
        )
        # Si el servidor no responde HEAD, hace fallback a GET
        if response.status_code == 405:
            response = requests.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                verify=verify_ssl,
                headers=request_headers,
                stream=True,
            )
            response.close()

        return dict(response.headers), response.status_code, response.url

    except (Timeout, ReqConnectionError, RequestException):
        return None, None, None

# Evalua Strict-Transport-Security
def evaluate_hsts(headers):
    value = headers.get("Strict-Transport-Security")

    if not value:
        return create_finding(
            finding_id="WEB-HH-001",
            title="Header Strict-Transport-Security (HSTS) ausente",
            severity=SEVERITY_HIGH,
            owasp_category=OWASP_CATEGORY,
            accessible_description=(
                "Su sitio no instruye a los navegadores a forzar conexiones seguras (HTTPS). "
                "Esto significa que un atacante podria interceptar la primera conexion de un "
                "usuario y degradarla a HTTP, exponiendo lo que escriba en el sitio."
            ),
            technical_description=(
                "El header Strict-Transport-Security (HSTS) no esta presente en la respuesta. "
                "HSTS instruye al navegador a comunicarse exclusivamente por HTTPS con el "
                "dominio durante el periodo definido por max-age, mitigando ataques de "
                "downgrade y SSL stripping."
            ),
            recommendation=(
                "Configurar el header en el servidor web con un max-age de al menos 31536000 "
                "segundos. Ejemplo: 'Strict-Transport-Security: max-age=31536000; "
                "includeSubDomains'."
            ),
            evidence={"header_present": False},
            resources=[
                "https://owasp.org/www-project-secure-headers/",
                "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security",
            ],
        )

    # max-age corto
    if "max-age=" in value.lower():
        try:
            max_age = int(value.lower().split("max-age=")[1].split(";")[0].strip())
            if max_age < 15768000:  # 6 meses
                return create_finding(
                    finding_id="WEB-HH-002",
                    title="Header HSTS con max-age inferior a 6 meses",
                    severity=SEVERITY_LOW,
                    owasp_category=OWASP_CATEGORY,
                    accessible_description=(
                        "El sitio fuerza HTTPS, pero por un periodo demasiado corto. Se "
                        "recomienda extender este periodo para mayor proteccion."
                    ),
                    technical_description=(
                        f"HSTS presente con max-age={max_age}. Se recomienda al menos "
                        f"15768000 segundos (6 meses), idealmente 31536000 (12 meses)."
                    ),
                    recommendation="Aumentar el valor de max-age a al menos 31536000 segundos.",
                    evidence={"header_present": True, "value": value, "max_age": max_age},
                )
        except (ValueError, IndexError):
            pass

    return None

# Evalua Content-Security-Policy
def evaluate_csp(headers):
    value = headers.get("Content-Security-Policy")

    if not value:
        return create_finding(
            finding_id="WEB-HH-003",
            title="Header Content-Security-Policy (CSP) ausente",
            severity=SEVERITY_HIGH,
            owasp_category=OWASP_CATEGORY,
            accessible_description=(
                "Su sitio no tiene una politica que limite que tipo de contenido externo puede "
                "cargarse. Esto facilita ataques en los que un atacante inyecta scripts "
                "maliciosos en el sitio (XSS) y roba informacion de los visitantes."
            ),
            technical_description=(
                "El header Content-Security-Policy no esta presente. CSP es la principal "
                "defensa en profundidad contra ataques XSS y de inyeccion de contenido. Define "
                "que origenes son legitimos para scripts, estilos, imagenes, frames, etc."
            ),
            recommendation=(
                "Implementar una politica CSP restrictiva. Una base inicial podria ser: "
                "\"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' "
                "data:; frame-ancestors 'self'\". Ajustar segun los recursos externos legitimos."
            ),
            evidence={"header_present": False},
            resources=[
                "https://content-security-policy.com/",
                "https://developer.mozilla.org/docs/Web/HTTP/CSP",
            ],
        )
    return None

# Evalua X-Frame-Options 
def evaluate_x_frame_options(headers):
    value = headers.get("X-Frame-Options")

    if not value:
        return create_finding(
            finding_id="WEB-HH-004",
            title="Header X-Frame-Options ausente",
            severity=SEVERITY_MEDIUM,
            owasp_category=OWASP_CATEGORY,
            accessible_description=(
                "Su sitio no impide que sea cargado dentro de otra pagina web mediante un "
                "marco invisible. Esto permite ataques en los que un usuario cree que esta "
                "haciendo clic en un sitio legitimo cuando en realidad esta interactuando "
                "con un sitio malicioso."
            ),
            technical_description=(
                "El header X-Frame-Options no esta presente. Este header previene ataques de "
                "clickjacking restringiendo donde puede ser embebido el sitio mediante iframes."
            ),
            recommendation=(
                "Configurar 'X-Frame-Options: DENY' o 'SAMEORIGIN'. Si ya se utiliza CSP con "
                "frame-ancestors, este header puede considerarse complementario."
            ),
            evidence={"header_present": False},
        )

    if value.upper() not in ["DENY", "SAMEORIGIN"]:
        return create_finding(
            finding_id="WEB-HH-005",
            title="Header X-Frame-Options con valor no estandar",
            severity=SEVERITY_LOW,
            owasp_category=OWASP_CATEGORY,
            accessible_description=(
                "Su sitio tiene una proteccion contra clickjacking, pero el valor configurado "
                "no es uno de los estandares reconocidos por todos los navegadores."
            ),
            technical_description=(
                f"X-Frame-Options presente con valor '{value}'. Los valores soportados de "
                f"forma uniforme son DENY y SAMEORIGIN."
            ),
            recommendation="Cambiar el valor a 'DENY' o 'SAMEORIGIN'.",
            evidence={"header_present": True, "value": value},
        )
    return None

# Evalua X-Content-Type-Options
def evaluate_x_content_type_options(headers):
    value = headers.get("X-Content-Type-Options")

    if not value:
        return create_finding(
            finding_id="WEB-HH-006",
            title="Header X-Content-Type-Options ausente",
            severity=SEVERITY_MEDIUM,
            owasp_category=OWASP_CATEGORY,
            accessible_description=(
                "Su sitio permite que el navegador adivine el tipo de contenido de los "
                "archivos servidos, lo que puede ser aprovechado para ejecutar archivos "
                "maliciosos disfrazados como otros formatos."
            ),
            technical_description=(
                "El header X-Content-Type-Options no esta presente. Sin este header, los "
                "navegadores aplican MIME-sniffing que puede inferir tipos distintos al "
                "Content-Type declarado."
            ),
            recommendation="Configurar 'X-Content-Type-Options: nosniff' en el servidor web.",
            evidence={"header_present": False},
        )

    if value.lower() != "nosniff":
        return create_finding(
            finding_id="WEB-HH-007",
            title="Header X-Content-Type-Options con valor incorrecto",
            severity=SEVERITY_LOW,
            owasp_category=OWASP_CATEGORY,
            accessible_description=(
                "El header esta presente pero con un valor que no protege adecuadamente "
                "contra ataques de tipo MIME-sniffing."
            ),
            technical_description=(
                f"X-Content-Type-Options presente con valor '{value}'. El unico valor "
                f"valido es 'nosniff'."
            ),
            recommendation="Cambiar el valor a 'nosniff'.",
            evidence={"header_present": True, "value": value},
        )
    return None

# Evalua Referrer-Policy
def evaluate_referrer_policy(headers):

    value = headers.get("Referrer-Policy")

    if not value:
        return create_finding(
            finding_id="WEB-HH-008",
            title="Header Referrer-Policy ausente",
            severity=SEVERITY_LOW,
            owasp_category=OWASP_CATEGORY,
            accessible_description=(
                "Su sitio no controla que informacion se comparte cuando un usuario hace clic "
                "en un enlace hacia otro sitio. Esto puede filtrar URLs internas o datos "
                "sensibles a sitios de terceros."
            ),
            technical_description=(
                "El header Referrer-Policy no esta presente. Sin esta politica, los "
                "navegadores envian por defecto el referrer completo a destinos externos."
            ),
            recommendation=(
                "Configurar 'Referrer-Policy: strict-origin-when-cross-origin' o un valor "
                "mas restrictivo como 'no-referrer'."
            ),
            evidence={"header_present": False},
        )
    return None

# Evalua Permissions-Policy
def evaluate_permissions_policy(headers):
    value = headers.get("Permissions-Policy") or headers.get("Feature-Policy")

    if not value:
        return create_finding(
            finding_id="WEB-HH-009",
            title="Header Permissions-Policy ausente",
            severity=SEVERITY_LOW,
            owasp_category=OWASP_CATEGORY,
            accessible_description=(
                "Su sitio no restringe que funciones del navegador (camara, microfono, "
                "ubicacion, etc.) pueden ser solicitadas. Definir esta politica reduce el "
                "impacto en caso de un ataque XSS."
            ),
            technical_description=(
                "El header Permissions-Policy no esta presente. Este header permite habilitar "
                "o deshabilitar APIs del navegador como geolocalizacion, camara, microfono, etc."
            ),
            recommendation=(
                "Definir una politica restrictiva. Ejemplo: "
                "'Permissions-Policy: geolocation=(), microphone=(), camera=()'."
            ),
            evidence={"header_present": False},
        )
    return None

# Detecta divulgacion excesiva de informacion del servidor
def evaluate_server_disclosure(headers):
    server = headers.get("Server", "")
    x_powered_by = headers.get("X-Powered-By", "")

    if x_powered_by:
        return create_finding(
            finding_id="WEB-HH-010",
            title="Header X-Powered-By revela tecnologia del servidor",
            severity=SEVERITY_INFO,
            owasp_category=OWASP_CATEGORY,
            accessible_description=(
                "Su servidor anuncia publicamente que tecnologia usa. Aunque no es una "
                "vulnerabilidad por si misma, facilita a un atacante identificar fallos "
                "conocidos para esa version especifica."
            ),
            technical_description=(
                f"El header X-Powered-By esta presente con valor '{x_powered_by}'. Este "
                f"header divulga informacion sobre la pila tecnologica del servidor."
            ),
            recommendation=(
                "Eliminar el header X-Powered-By en la configuracion del servidor o framework "
                "(en PHP: 'expose_php = Off' en php.ini)."
            ),
            evidence={"x_powered_by": x_powered_by, "server": server},
        )
    return None

 # Ejecuta el scanner completo. Retorna la estructura de resultados definida en utils/model.py
def run(url, timeout=15, verify_ssl=True):
    log = get_logger()
    log.info(f"[Headers HTTP] Iniciando analisis de {url}")

    result = create_scanner_result(SCANNER_NAME)
    start = time.time()

    headers, status_code, final_url = fetch_headers(url, timeout, verify_ssl)

    if headers is None:
        result["status"] = STATUS_FAILED
        result["error_message"] = "No fue posible conectar con el sitio."
        result["duration_seconds"] = round(time.time() - start, 2)
        log.error(f"[Headers HTTP] Fallo la conexion con {url}")
        return result

    log.info(f"[Headers HTTP] Respuesta HTTP {status_code} - {len(headers)} headers recibidos")

    evaluators = [
        evaluate_hsts,
        evaluate_csp,
        evaluate_x_frame_options,
        evaluate_x_content_type_options,
        evaluate_referrer_policy,
        evaluate_permissions_policy,
        evaluate_server_disclosure,
    ]

    for evaluator in evaluators:
        try:
            finding = evaluator(headers)
            if finding:
                result["findings"].append(finding)
        except Exception as e:
            log.warning(f"[Headers HTTP] Error en evaluador {evaluator.__name__}: {e}")

    result["status"] = STATUS_COMPLETED
    result["score"] = calculate_score(result["findings"])
    result["duration_seconds"] = round(time.time() - start, 2)

    log.info(
        f"[Headers HTTP] Finalizado - {len(result['findings'])} hallazgos - "
        f"puntaje {result['score']}/100"
    )
    return result
