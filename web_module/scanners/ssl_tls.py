
import ssl
import socket
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

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
    STATUS_PARTIAL,
    STATUS_FAILED,
)
from toolkitTCU.web_module.utils.logger import get_logger

SCANNER_NAME = "Auditor SSL/TLS"
OWASP_CATEGORY = "OWASP A02:2021 - Cryptographic Failures"

PROTOCOLS_TO_TEST = {
    "SSLv3": ssl.TLSVersion.SSLv3 if hasattr(ssl.TLSVersion, "SSLv3") else None,
    "TLSv1.0": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}

WEAK_CIPHER_KEYWORDS = ["RC4", "DES", "3DES", "MD5", "EXPORT", "NULL", "anon"]

def extract_host_port(url):

    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port if parsed.port else (443 if parsed.scheme == "https" else 80)
    return host, port

def fetch_certificate(host, port, timeout=15):

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                verify_context = ssl.create_default_context()
                try:
                    with socket.create_connection((host, port), timeout=timeout) as s2:
                        with verify_context.wrap_socket(s2, server_hostname=host) as ss2:
                            cert = ss2.getpeercert()
                            return cert, cert_bin, ss2.version()
                except ssl.SSLCertVerificationError as e:
                    return {"_invalid": True, "_error": str(e)}, cert_bin, ssock.version()
    except Exception:
        return None, None, None

def evaluate_certificate(cert, tls_version):
    findings = []

    if cert is None:
        findings.append(create_finding(
            finding_id="WEB-SSL-001",
            title="No fue posible establecer conexion SSL/TLS",
            severity=SEVERITY_CRITICAL,
            owasp_category=OWASP_CATEGORY,
            accessible_description=(
                "Su sitio no respondio a una conexion segura. Esto puede indicar que el sitio "
                "no soporta HTTPS o que su certificado tiene un problema grave que impide "
                "establecer la conexion."
            ),
            technical_description=(
                "Fallo el handshake SSL/TLS contra el host objetivo. No fue posible obtener "
                "informacion del certificado."
            ),
            recommendation=(
                "Verificar que el servidor tenga un certificado SSL valido instalado y que "
                "el puerto 443 este accesible."
            ),
        ))
        return findings

    if cert.get("_invalid"):
        findings.append(create_finding(
            finding_id="WEB-SSL-002",
            title="Certificado SSL invalido o no confiable",
            severity=SEVERITY_CRITICAL,
            owasp_category=OWASP_CATEGORY,
            accessible_description=(
                "El certificado del sitio no es valido. Los visitantes veran advertencias en "
                "su navegador y no podran confiar en que se estan conectando al sitio "
                "correcto, lo que daria oportunidad a ataques de suplantacion."
            ),
            technical_description=f"Fallo de verificacion: {cert.get('_error', 'desconocido')}",
            recommendation=(
                "Renovar el certificado mediante una autoridad certificadora confiable. "
                "Para ONGs, Let's Encrypt ofrece certificados gratuitos."
            ),
            evidence={"verification_error": cert.get("_error")},
            resources=["https://letsencrypt.org/"],
        ))
        return findings

    if "notAfter" in cert:
        try:
            expiry_date = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            expiry_date = expiry_date.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_remaining = (expiry_date - now).days

            if days_remaining < 0:
                findings.append(create_finding(
                    finding_id="WEB-SSL-003",
                    title="Certificado SSL expirado",
                    severity=SEVERITY_CRITICAL,
                    owasp_category=OWASP_CATEGORY,
                    accessible_description=(
                        "El certificado de seguridad de su sitio ya esta vencido."
                    ),
                    technical_description=(
                        f"El certificado expiro hace {abs(days_remaining)} dias "
                        f"(notAfter: {cert['notAfter']})."
                    ),
                    recommendation="Renovar el certificado de inmediato.",
                    evidence={"expiry_date": cert["notAfter"], "days_remaining": days_remaining},
                ))
            elif days_remaining < 15:
                findings.append(create_finding(
                    finding_id="WEB-SSL-004",
                    title="Certificado SSL proximo a expirar",
                    severity=SEVERITY_HIGH,
                    owasp_category=OWASP_CATEGORY,
                    accessible_description=(
                        f"El certificado de su sitio expira en {days_remaining} dias. Si no "
                        f"se renueva a tiempo los visitantes veran advertencias graves."
                    ),
                    technical_description=(
                        f"El certificado expira el {cert['notAfter']} ({days_remaining} dias)."
                    ),
                    recommendation=(
                        "Renovar el certificado pronto. Considere automatizar la renovacion "
                    ),
                    evidence={"expiry_date": cert["notAfter"], "days_remaining": days_remaining},
                ))
            elif days_remaining < 30:
                findings.append(create_finding(
                    finding_id="WEB-SSL-005",
                    title="Certificado SSL expira en menos de 30 dias",
                    severity=SEVERITY_MEDIUM,
                    owasp_category=OWASP_CATEGORY,
                    accessible_description=(
                        f"Quedan {days_remaining} dias para que el certificado expire. "
                        f"Es momento de planificar la renovacion."
                    ),
                    technical_description=(
                        f"El certificado expira el {cert['notAfter']} ({days_remaining} dias)."
                    ),
                    recommendation="Programar la renovacion del certificado en las proximas semanas.",
                    evidence={"expiry_date": cert["notAfter"], "days_remaining": days_remaining},
                ))
        except (ValueError, KeyError):
            pass

    return findings

def test_protocol(host, port, protocol_version, timeout=10):
    if protocol_version is None:
        return False

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        context.minimum_version = protocol_version
        context.maximum_version = protocol_version
    except (ValueError, AttributeError):
        return False

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                return True
    except Exception:
        return False

def evaluate_protocols(host, port, timeout=10):
    findings = []
    supported = {}

    for name, version in PROTOCOLS_TO_TEST.items():
        supported[name] = test_protocol(host, port, version, timeout)

    if supported.get("SSLv3"):
        findings.append(create_finding(
            finding_id="WEB-SSL-010",
            title="Servidor soporta SSLv3 (vulnerable a POODLE)",
            severity=SEVERITY_CRITICAL,
            owasp_category=OWASP_CATEGORY,
            accessible_description=(
                "Su servidor permite conexiones usando un protocolo de seguridad muy antiguo "
                "(SSLv3) que tiene fallos conocidos. Un atacante podria descifrar partes del "
                "trafico cifrado entre los visitantes y el sitio."
            ),
            technical_description=(
                "El servidor acepta handshakes SSLv3, vulnerable al ataque POODLE "
                "(CVE-2014-3566). El padding de cifradores en modo CBC permite a un atacante "
                "descifrar bytes del trafico cifrado."
            ),
            recommendation="Deshabilitar SSLv3 en la configuracion del servidor web inmediatamente.",
            evidence={"protocol": "SSLv3", "supported": True},
            resources=["https://www.openssl.org/~bodo/ssl-poodle.pdf"],
        ))

    if supported.get("TLSv1.0"):
        findings.append(create_finding(
            finding_id="WEB-SSL-011",
            title="Servidor soporta TLS 1.0 (protocolo obsoleto)",
            severity=SEVERITY_HIGH,
            owasp_category=OWASP_CATEGORY,
            accessible_description=(
                "Su servidor permite conexiones usando una version antigua del protocolo de "
                "seguridad que ya esta declarada obsoleta y no debe usarse en sitios actuales."
            ),
            technical_description=(
                "TLS 1.0 esta deprecado por la IETF (RFC 8996) y por NIST SP 800-52. "
                "Presenta debilidades estructurales y no debe usarse."
            ),
            recommendation="Configurar el servidor para aceptar unicamente TLS 1.2 y TLS 1.3.",
            evidence={"protocol": "TLSv1.0", "supported": True},
        ))

    if supported.get("TLSv1.1"):
        findings.append(create_finding(
            finding_id="WEB-SSL-012",
            title="Servidor soporta TLS 1.1 (protocolo obsoleto)",
            severity=SEVERITY_HIGH,
            owasp_category=OWASP_CATEGORY,
            accessible_description=(
                "Su servidor permite conexiones usando TLS 1.1, una version del protocolo "
                "que ya no se considera segura y fue formalmente deprecada."
            ),
            technical_description="TLS 1.1 esta deprecado por la IETF (RFC 8996) desde 2021.",
            recommendation="Deshabilitar TLS 1.1 y aceptar solo TLS 1.2 y TLS 1.3.",
            evidence={"protocol": "TLSv1.1", "supported": True},
        ))

    if not supported.get("TLSv1.3") and supported.get("TLSv1.2"):
        findings.append(create_finding(
            finding_id="WEB-SSL-013",
            title="Servidor no soporta TLS 1.3",
            severity=SEVERITY_LOW,
            owasp_category=OWASP_CATEGORY,
            accessible_description=(
                "Su servidor no soporta la version mas moderna del protocolo de seguridad "
                "(TLS 1.3), que ofrece mejor rendimiento y mayor seguridad."
            ),
            technical_description="No se logro establecer conexion con TLS 1.3.",
            recommendation=(
                "Si la version del servidor web lo permite, habilitar TLS 1.3 para mejorar "
                "rendimiento y seguridad."
            ),
            evidence={"protocol": "TLSv1.3", "supported": False},
        ))

    if not supported.get("TLSv1.2") and not supported.get("TLSv1.3"):
        findings.append(create_finding(
            finding_id="WEB-SSL-014",
            title="Servidor no soporta TLS 1.2 ni TLS 1.3",
            severity=SEVERITY_CRITICAL,
            owasp_category=OWASP_CATEGORY,
            accessible_description=(
                "Su servidor no soporta ninguna version moderna del protocolo de seguridad. "
                "Esto significa que las conexiones podrian estar usando protocolos antiguos "
                "y vulnerables."
            ),
            technical_description="No se establecio conexion ni con TLS 1.2 ni con TLS 1.3.",
            recommendation="Habilitar TLS 1.2 y TLS 1.3 en el servidor web inmediatamente.",
        ))

    return findings, supported

def evaluate_ciphers(host, port, timeout=10):
    findings = []
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                if cipher:
                    cipher_name = cipher[0]
                    bits = cipher[2]

                    for kw in WEAK_CIPHER_KEYWORDS:
                        if kw in cipher_name.upper():
                            findings.append(create_finding(
                                finding_id="WEB-SSL-020",
                                title=f"Servidor negocia cifrado debil ({cipher_name})",
                                severity=SEVERITY_HIGH,
                                owasp_category=OWASP_CATEGORY,
                                accessible_description=(
                                    "Su servidor utiliza un metodo de cifrado considerado "
                                    "debil. Esto reduce la efectividad real de la proteccion "
                                    "que ofrece HTTPS."
                                ),
                                technical_description=(
                                    f"Cifrado negociado: {cipher_name} ({bits} bits). "
                                    f"Contiene el patron '{kw}' considerado debil por NIST."
                                ),
                                recommendation=(
                                    "Eliminar cifrados debiles (RC4, DES, 3DES, EXPORT, NULL) "
                                    "y priorizar suites con Perfect Forward Secrecy (ECDHE)."
                                ),
                                evidence={"cipher": cipher_name, "bits": bits},
                            ))
                            break

                    if bits and bits < 128:
                        findings.append(create_finding(
                            finding_id="WEB-SSL-021",
                            title=f"Cifrado con longitud de clave insuficiente ({bits} bits)",
                            severity=SEVERITY_HIGH,
                            owasp_category=OWASP_CATEGORY,
                            accessible_description=(
                                "El metodo de cifrado utilizado tiene una longitud de clave "
                                "menor a la recomendada actualmente."
                            ),
                            technical_description=(
                                f"Cifrado {cipher_name} con {bits} bits. Se recomienda 128+ bits."
                            ),
                            recommendation="Configurar suites de cifrado con al menos 128 bits.",
                            evidence={"cipher": cipher_name, "bits": bits},
                        ))
    except Exception:
        pass

    return findings

def evaluate_robot(supported):
    if supported.get("TLSv1.0") or supported.get("TLSv1.1"):
        return create_finding(
            finding_id="WEB-SSL-030",
            title="Posible exposicion a vulnerabilidades en cifrados RSA antiguos",
            severity=SEVERITY_INFO,
            owasp_category=OWASP_CATEGORY,
            accessible_description=(
                "El soporte de versiones antiguas del protocolo TLS junto al uso historico "
                "de cifrados RSA puede exponer al sitio a vulnerabilidades como ROBOT. Se "
                "recomienda una verificacion especializada."
            ),
            technical_description=(
                "ROBOT (Return Of Bleichenbacher's Oracle Threat) afecta implementaciones "
                "de RSA PKCS#1 v1.5. La verificacion definitiva requiere herramientas "
                "especializadas como testssl.sh o sslyze."
            ),
            recommendation=(
                "Ejecutar herramientas especializadas (sslyze, testssl.sh) para confirmar. "
                "Deshabilitar TLS 1.0/1.1 elimina los vectores mas comunes de explotacion."
            ),
        )
    return None

def run(url, timeout=15):
    log = get_logger()
    log.info(f"[SSL/TLS] Iniciando analisis de {url}")

    result = create_scanner_result(SCANNER_NAME)
    start = time.time()

    host, port = extract_host_port(url)
    if not host:
        result["status"] = STATUS_FAILED
        result["error_message"] = "URL invalida: no se pudo extraer el host."
        result["duration_seconds"] = round(time.time() - start, 2)
        return result

    parsed = urlparse(url)
    if parsed.scheme == "http":
        result["status"] = STATUS_COMPLETED
        result["findings"].append(create_finding(
            finding_id="WEB-SSL-040",
            title="Sitio servido sobre HTTP sin cifrado",
            severity=SEVERITY_CRITICAL,
            owasp_category=OWASP_CATEGORY,
            accessible_description=(
                "Su sitio se sirve sin cifrado. Toda la informacion entre los visitantes y "
                "el sitio viaja en texto plano y puede ser interceptada en redes publicas."
            ),
            technical_description="La URL utiliza el esquema http://, sin TLS.",
            recommendation=(
                "Migrar el sitio a HTTPS. Let's Encrypt ofrece certificados gratuitos "
                "y configurar redirecciones 301 desde HTTP."
            ),
            resources=["https://letsencrypt.org/"],
        ))
        result["score"] = calculate_score(result["findings"])
        result["duration_seconds"] = round(time.time() - start, 2)
        log.warning(f"[SSL/TLS] Sitio sin HTTPS")
        return result

    log.info(f"[SSL/TLS] Obteniendo certificado de {host}:{port}")
    cert, cert_bin, tls_version = fetch_certificate(host, port, timeout)
    result["findings"].extend(evaluate_certificate(cert, tls_version))

    if cert is None:
        result["status"] = STATUS_PARTIAL
        result["error_message"] = "No se pudo establecer conexion SSL/TLS."
        result["score"] = calculate_score(result["findings"])
        result["duration_seconds"] = round(time.time() - start, 2)
        return result

    log.info(f"[SSL/TLS] Probando versiones de protocolo")
    protocol_findings, supported = evaluate_protocols(host, port, timeout)
    result["findings"].extend(protocol_findings)

    log.info(f"[SSL/TLS] Analizando cifrados")
    result["findings"].extend(evaluate_ciphers(host, port, timeout))

    robot_finding = evaluate_robot(supported)
    if robot_finding:
        result["findings"].append(robot_finding)

    result["status"] = STATUS_COMPLETED
    result["score"] = calculate_score(result["findings"])
    result["duration_seconds"] = round(time.time() - start, 2)

    log.info(
        f"[SSL/TLS] Finalizado - {len(result['findings'])} hallazgos - "
        f"puntaje {result['score']}/100"
    )
    return result
