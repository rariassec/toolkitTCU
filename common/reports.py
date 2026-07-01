
import json
import os
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from toolkitTCU.common import findings as F

REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reportes"
)

_SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#C0392B"),
    "HIGH": colors.HexColor("#E67E22"),
    "MEDIUM": colors.HexColor("#F1C40F"),
    "LOW": colors.HexColor("#3498DB"),
    "INFO": colors.HexColor("#7F8C8D"),
}

def ensure_reports_dir():
    os.makedirs(REPORTS_DIR, exist_ok=True)
    return REPORTS_DIR

def _timestamped_path(prefix, extension):
    ensure_reports_dir()
    name = f"{prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{extension}"
    return os.path.join(REPORTS_DIR, name)

def save_json_report(data, prefix):
    path = _timestamped_path(prefix, "json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    return path

def save_pdf_report(report, prefix, title="Reporte de seguridad"):
    path = _timestamped_path(prefix, "pdf")
    doc = SimpleDocTemplate(
        path, pagesize=letter,
        rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("rep_title", parent=styles["Title"], fontSize=18)
    heading = ParagraphStyle("rep_heading", parent=styles["Heading2"], fontSize=13)
    body = ParagraphStyle("rep_body", parent=styles["Normal"], fontSize=10, leading=13)
    small = ParagraphStyle("rep_small", parent=styles["Normal"], fontSize=9, textColor=colors.grey)

    story = []
    story.append(Paragraph(title, title_style))
    story.append(Paragraph(
        f"Generado el {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", small
    ))
    story.append(Spacer(1, 14))

    summary = report.get("executive_summary", {})
    counts = summary.get("severity_count", {})
    resumen_data = [
        ["Puntaje global", f"{summary.get('global_score', '-')}/100"],
        ["Total de hallazgos", str(summary.get("total_findings", 0))],
        ["Críticos / Altos", f"{counts.get('CRITICAL', 0)} / {counts.get('HIGH', 0)}"],
        ["Medios / Bajos / Info",
         f"{counts.get('MEDIUM', 0)} / {counts.get('LOW', 0)} / {counts.get('INFO', 0)}"],
    ]
    t = Table(resumen_data, colWidths=[200, 320])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F2F4F4")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.grey),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D5DBDB")),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(Paragraph("Resumen ejecutivo", heading))
    story.append(t)
    story.append(Spacer(1, 16))

    modules = report.get("modules", {})
    if not modules:
        story.append(Paragraph("No se registraron hallazgos.", body))
    for result in modules.values():
        story.append(Paragraph(result.get("display_name", result.get("module", "")), heading))
        if result.get("summary"):
            resumen = " | ".join(f"{k}: {v}" for k, v in result["summary"].items())
            story.append(Paragraph(resumen, small))
        findings = F.sort_findings(result.get("findings", []))
        if not findings:
            story.append(Paragraph("Sin hallazgos en este módulo.", body))
        for f in findings:
            sev = f.get("severity", "INFO")
            color = _SEVERITY_COLORS.get(sev, colors.black)
            etiqueta = ParagraphStyle(
                "sev", parent=body, textColor=color, fontName="Helvetica-Bold"
            )
            story.append(Spacer(1, 6))
            story.append(Paragraph(f"[{sev}] {f.get('title', '')}", etiqueta))
            if f.get("description"):
                story.append(Paragraph(f["description"], body))
            if f.get("recommendation"):
                story.append(Paragraph(f"Recomendación: {f['recommendation']}", body))
        story.append(Spacer(1, 14))

    doc.build(story)
    return path

def save_module_report(module_result, prefix, title):
    report = F.create_unified_report()
    F.add_module_result(report, module_result)
    json_path = save_json_report(report, prefix)
    pdf_path = save_pdf_report(report, prefix, title)
    return json_path, pdf_path

def save_unified_report(report, prefix="reporte_unificado", title="Reporte unificado del toolkit"):
    json_path = save_json_report(report, prefix)
    pdf_path = save_pdf_report(report, prefix, title)
    return json_path, pdf_path
