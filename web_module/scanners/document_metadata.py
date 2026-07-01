
import time
import os
import re
import tempfile
import requests
from urllib.parse import urljoin, urlparse
from collections import deque
from requests.exceptions import RequestException

from toolkitTCU.web_module.utils.model import (
    create_finding,
    create_scanner_result,
    calculate_score,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFO,
    STATUS_COMPLETED,
    STATUS_PARTIAL,
    STATUS_FAILED,
)
from toolkitTCU.web_module.utils.logger import get_logger

SCANNER_NAME = "Analizador de Metadatos en Documentos"
OWASP_CATEGORY = "OWASP A01:2021 - Broken Access Control / Information Disclosure"

DOCUMENT_EXTENSIONS = [".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt"]

INTERNAL_PATH_PATTERNS = [
    r"C:\\Users\\[^\\]+",
    r"/home/[^/\s]+",
    r"/Users/[^/\s]+",
    r"\\\\[^\\]+\\[^\\]+",
]

def basic_crawl(base_url, max_pages=15, max_depth=2, timeout=10):

    try:
        from bs4 import BeautifulSoup
    except ImportError:
        return [], "La libreria beautifulsoup4 no esta instalada"

    base_domain = urlparse(base_url).netloc
    visited = set()
    documents_found = []
    queue = deque([(base_url, 0)])

    while queue and len(visited) < max_pages:
        current_url, depth = queue.popleft()

        if current_url in visited or depth > max_depth:
            continue
        visited.add(current_url)

        try:
            response = requests.get(
                current_url,
                timeout=timeout,
                allow_redirects=True,
                headers={"User-Agent": "ONG-Security-Tool"},
                verify=False,
            )
        except RequestException:
            continue

        if response.status_code != 200:
            continue

        content_type = response.headers.get("Content-Type", "")
        if "text/html" not in content_type.lower():
            continue

        try:
            soup = BeautifulSoup(response.text, "html.parser")
        except Exception:
            continue

        for a in soup.find_all("a", href=True):
            href = a["href"]
            full_url = urljoin(current_url, href)
            parsed_url = urlparse(full_url)

            if parsed_url.netloc != base_domain:
                continue

            path = parsed_url.path.lower()

            if any(path.endswith(ext) for ext in DOCUMENT_EXTENSIONS):
                if full_url not in documents_found:
                    documents_found.append(full_url)
            else:
                if full_url not in visited and depth + 1 <= max_depth:
                    queue.append((full_url, depth + 1))

    return documents_found, None

def download_document(url, temp_dir, timeout=15):
    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": "ONG-Security-Tool"},
            verify=False,
            stream=True,
        )
        if response.status_code != 200:
            return None

        max_bytes = 10 * 1024 * 1024
        filename = os.path.basename(urlparse(url).path) or "document"
        local_path = os.path.join(temp_dir, filename)

        downloaded = 0
        with open(local_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    if downloaded > max_bytes:
                        return None

        return local_path
    except Exception:
        return None

def extract_pdf_metadata(file_path):
    metadata = {}
    try:
        try:
            from pypdf import PdfReader
        except ImportError:
            from PyPDF2 import PdfReader

        with open(file_path, "rb") as f:
            reader = PdfReader(f)
            info = reader.metadata or {}
            for k, v in info.items():
                key = k.lstrip("/") if isinstance(k, str) else str(k)
                metadata[key] = str(v) if v else ""
    except Exception as e:
        return None, str(e)

    return metadata, None

def extract_docx_metadata(file_path):
    try:
        from docx import Document
    except ImportError:
        return None, "python-docx no esta instalado"

    try:
        doc = Document(file_path)
        props = doc.core_properties
        metadata = {
            "Author": props.author or "",
            "Title": props.title or "",
            "Subject": props.subject or "",
            "LastModifiedBy": props.last_modified_by or "",
            "Created": str(props.created) if props.created else "",
            "Modified": str(props.modified) if props.modified else "",
            "Company": props.category or "",
            "Comments": props.comments or "",
        }
        return metadata, None
    except Exception as e:
        return None, str(e)

def extract_xlsx_metadata(file_path):
    try:
        from openpyxl import load_workbook
    except ImportError:
        return None, "openpyxl no esta instalado"

    try:
        wb = load_workbook(file_path, read_only=True, data_only=True)
        props = wb.properties
        metadata = {
            "Creator": props.creator or "",
            "Title": props.title or "",
            "Subject": props.subject or "",
            "LastModifiedBy": props.lastModifiedBy or "",
            "Created": str(props.created) if props.created else "",
            "Modified": str(props.modified) if props.modified else "",
            "Company": props.company or "",
        }
        wb.close()
        return metadata, None
    except Exception as e:
        return None, str(e)

def extract_metadata(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    if ext == ".pdf":
        return extract_pdf_metadata(file_path)
    if ext == ".docx":
        return extract_docx_metadata(file_path)
    if ext == ".xlsx":
        return extract_xlsx_metadata(file_path)
    return {}, "Formato no soportado para extraccion automatica"

def detect_internal_paths(metadata):
    detected_paths = []
    for key, value in metadata.items():
        if not value:
            continue
        value_str = str(value)
        for pattern in INTERNAL_PATH_PATTERNS:
            matches = re.findall(pattern, value_str)
            for m in matches:
                detected_paths.append({"field": key, "path": m})
    return detected_paths

def build_findings_for_document(url, metadata):
    findings = []

    if not metadata:
        return findings

    author = metadata.get("Author") or metadata.get("Creator", "")
    if author:
        findings.append(create_finding(
            finding_id=f"WEB-MD-{abs(hash(url + 'author')) % 1000:03d}",
            title="Documento público expone nombre de autor",
            severity=SEVERITY_LOW,
            owasp_category=OWASP_CATEGORY,
            accessible_description=(
                f"Un documento publicado en su sitio incluye el nombre de su autor "
                f"('{author}'). Esta información puede ser útil para ataques de "
                f"ingeniería social dirigidos a esa persona."
            ),
            technical_description=(
                f"El documento {url} contiene metadatos de autor: '{author}'."
            ),
            recommendation=(
                "Antes de publicar documentos, eliminar metadatos sensibles. En Word/Excel "
                "esto se hace mediante 'Inspeccionar documento' antes de exportar."
            ),
            evidence={"url": url, "field": "Author", "value": author},
        ))

    software = metadata.get("Producer") or metadata.get("Creator") or ""
    if software and any(w in software for w in ["Microsoft", "OpenOffice", "LibreOffice", "Acrobat"]):
        version_match = re.search(r"(\d+\.\d+(?:\.\d+)?)", software)
        if version_match:
            findings.append(create_finding(
                finding_id=f"WEB-MD-{abs(hash(url + 'sw')) % 1000:03d}",
                title="Documento revela versión de software de creación",
                severity=SEVERITY_INFO,
                owasp_category=OWASP_CATEGORY,
                accessible_description=(
                    f"Un documento publicado contiene información sobre el software con que "
                    f"fue creado ('{software}'). Esto puede ayudar a un atacante a perfilar "
                    f"el entorno tecnológico de la organización."
                ),
                technical_description=f"Software detectado: {software}",
                recommendation="Limpiar metadatos antes de publicar documentos.",
                evidence={"url": url, "software": software},
            ))

    paths = detect_internal_paths(metadata)
    if paths:
        examples = ", ".join(set([p["path"] for p in paths[:3]]))
        findings.append(create_finding(
            finding_id=f"WEB-MD-{abs(hash(url + 'paths')) % 1000:03d}",
            title="Documento expone rutas internas del sistema",
            severity=SEVERITY_MEDIUM,
            owasp_category=OWASP_CATEGORY,
            accessible_description=(
                f"Un documento publicado contiene rutas de archivos internos de la "
                f"computadora donde se creó (por ejemplo: {examples}). Esto revela "
                f"detalles del entorno de trabajo de la organización."
            ),
            technical_description=(
                f"Se detectaron {len(paths)} rutas internas en metadatos del documento."
            ),
            recommendation=(
                "Antes de publicar documentos, eliminar metadatos. En PDF utilizar la "
                "opción 'Sanitizar documento' de Acrobat o herramientas como exiftool."
            ),
            evidence={"url": url, "detected_paths": paths[:5]},
        ))

    return findings

def run(url, max_documents=10, max_pages=15, timeout=10):
    log = get_logger()
    log.info(f"[Metadatos] Iniciando analisis de {url}")
    requests.packages.urllib3.disable_warnings()

    result = create_scanner_result(SCANNER_NAME)
    start = time.time()

    log.info(f"[Metadatos] Buscando documentos (max {max_pages} paginas)")
    documents, crawl_error = basic_crawl(url, max_pages=max_pages, timeout=timeout)

    if crawl_error:
        result["status"] = STATUS_FAILED
        result["error_message"] = crawl_error
        result["duration_seconds"] = round(time.time() - start, 2)
        return result

    log.info(f"[Metadatos] {len(documents)} documentos encontrados")

    if not documents:
        result["status"] = STATUS_COMPLETED
        result["findings"].append(create_finding(
            finding_id="WEB-MD-000",
            title="No se detectaron documentos públicos en el crawling",
            severity=SEVERITY_INFO,
            owasp_category=OWASP_CATEGORY,
            accessible_description=(
                "El análisis no encontró documentos públicos (PDF, DOCX, XLSX) accesibles "
                "desde la página principal. Esto no significa que no existan; el crawling "
                "es limitado."
            ),
            technical_description="El crawler no encontró enlaces a documentos en las páginas analizadas.",
            recommendation="Si su sitio aloja documentos, verificar manualmente sus metadatos.",
        ))
        result["score"] = calculate_score(result["findings"])
        result["duration_seconds"] = round(time.time() - start, 2)
        return result

    documents = documents[:max_documents]

    documents_processed = 0
    documents_failed = 0

    with tempfile.TemporaryDirectory() as temp_dir:
        for doc_url in documents:
            log.info(f"[Metadatos] Descargando: {doc_url}")
            local_path = download_document(doc_url, temp_dir, timeout)

            if local_path is None:
                documents_failed += 1
                continue

            metadata, error = extract_metadata(local_path)
            if metadata is None:
                documents_failed += 1
                log.warning(f"[Metadatos] Error extrayendo de {doc_url}: {error}")
                continue

            documents_processed += 1
            doc_findings = build_findings_for_document(doc_url, metadata)
            result["findings"].extend(doc_findings)

            try:
                os.remove(local_path)
            except OSError:
                pass

    if documents_processed == 0 and documents_failed > 0:
        result["status"] = STATUS_PARTIAL
        result["error_message"] = f"No se pudo procesar ninguno de los {documents_failed} documentos detectados."
    else:
        result["status"] = STATUS_COMPLETED

    result["score"] = calculate_score(result["findings"])
    result["duration_seconds"] = round(time.time() - start, 2)

    log.info(
        f"[Metadatos] Finalizado - {documents_processed} documentos analizados - "
        f"{len(result['findings'])} hallazgos - puntaje {result['score']}/100"
    )
    return result
