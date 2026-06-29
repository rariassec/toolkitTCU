from datetime import datetime
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from toolkitTCU.network_module.core.config import GRAPHICS_FOLDER, REPORT_FOLDER
from reportlab.platypus import Image

import os

def export_report(
    results,
    target,
    ports,
    protocol_name,
    report_name
):
    current_date = datetime.now().strftime("%Y-%m-%d")
    current_time = datetime.now().strftime("%H:%M:%S")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    filename = (
        f"{REPORT_FOLDER}/"
        f"{report_name}_Reporte_{timestamp}.pdf"
    )
    document = SimpleDocTemplate(
        filename,
        pagesize=letter
    )
    styles = getSampleStyleSheet()
    elements = []

    title = Paragraph(
        f"Reporte Escaneo {protocol_name}",
        styles["Title"]
    )
    elements.append(title)
    elements.append(Spacer(1, 20))

    info_text = f"""
    <b>Fecha:</b> {current_date}<br/>
    <b>Hora:</b> {current_time}<br/>
    <b>IP/Rango objetivo:</b> {target}<br/>
    <b>Protocolo escaneado:</b> {protocol_name}<br/>
    <b>Puertos escaneados:</b> {ports}<br/>
    """
    info_paragraph = Paragraph(
        info_text,
        styles["BodyText"]
    )
    elements.append(info_paragraph)
    elements.append(Spacer(1, 20))

    table_data = [[
        "IP",
        "Puerto",
        "Protocolo",
        "Estado",
        "Servicio",
        "Version"
    ]]
    for result in results:
        table_data.append([
            result["ip"],
            str(result["port"]),
            result["protocol"],
            result["state"],
            result["service"],
            result["version"]
        ])
    table = Table(table_data)

    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    elements.append(table)
    document.build(elements)
    print(f"\nReporte PDF generado: {filename}")

def export_tcp_report_pdf(
    results,
    target,
    ports
):
    export_report(
        results,
        target,
        ports,
        "TCP",
        "EscaneoTCP"
    )
def export_udp_report_pdf(
    results,
    target,
    ports
):
    export_report(
        results,
        target,
        ports,
        "UDP",
        "EscaneoUDP"
    )

def export_custom_report_pdf(
    results,
    target,
    ports
):
    export_report(
        results,
        target,
        ports,
        "CUSTOM",
        "EscaneoCustom"
    )

def export_vulnerabilities_report_pdf(results):
    current_date = datetime.now().strftime("%Y-%m-%d")
    current_time = datetime.now().strftime("%H:%M:%S")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    filename = (
        f"{REPORT_FOLDER}/"
        f"ServiciosVulnerables_Reporte_{timestamp}.pdf"
    )
    document = SimpleDocTemplate(
        filename,
        pagesize=letter
    )
    styles = getSampleStyleSheet()
    elements = []

    title = Paragraph(
        "Reporte de servicios y versiones vulnerables",
        styles["Title"]
    )
    elements.append(title)
    elements.append(Spacer(1, 20))

    total_services = len(results)
    total_vulnerabilities = 0
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0

    for result in results:
        for vuln in result["vulnerabilities"]:
            total_vulnerabilities += 1
            severity = vuln["severity"]
            if severity == "CRITICAL":
                critical_count += 1
            elif severity == "HIGH":
                high_count += 1
            elif severity == "MEDIUM":
                medium_count += 1
            elif severity == "LOW":
                low_count += 1

    info_text = f"""
    <b>Fecha:</b> {current_date}<br/>
    <b>Hora:</b> {current_time}<br/>
    <b>Total servicios analizados:</b> {total_services}<br/>
    <b>Total vulnerabilidades encontradas:</b> {total_vulnerabilities}<br/>
    <b>Vulnerabilidades criticas:</b> {critical_count}<br/>
    <b>Vulnerabilidades altas:</b> {high_count}<br/>
    <b>Vulnerabilidades medias:</b> {medium_count}<br/>
    <b>Vulnerabilidades bajas:</b> {low_count}<br/>
    """
    info_paragraph = Paragraph(
        info_text,
        styles["BodyText"]
    )
    elements.append(info_paragraph)
    elements.append(Spacer(1, 20))

    table_data = [[
        "IP",
        "Puerto",
        "Protocolo",
        "Servicio",
        "Version detectada",
        "CVE",
        "Severidad",
        "CVSS"
    ]]
    for result in results:
        for vuln in result["vulnerabilities"]:
            table_data.append([
                result["ip"],
                str(result["port"]),
                result["protocol"],
                result["service"],
                result["version"],
                vuln["cve"],
                vuln["severity"],
                str(vuln["score"])
            ])
    table = Table(table_data)

    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 7),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    elements.append(table)
    document.build(elements)
    print(f"\nReporte PDF generado: {filename}")

def export_suspicious_report_pdf(
    results,
    monitoring_time,
    analysis_type
):
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle
    )
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors
    from datetime import datetime
    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )
    filename = (
        f"{REPORT_FOLDER}/"
        f"ConexionesSospechosas_{timestamp}.pdf"
    )
    document = SimpleDocTemplate(
        filename,
        pagesize=letter
    )
    styles = getSampleStyleSheet()
    elements = []

    title = Paragraph(
        "Reporte detector conexiones sospechosas",
        styles["Title"]
    )
    elements.append(title)
    elements.append(Spacer(1, 20))

    info = f"""
    <b>Fecha:</b> {datetime.now().strftime("%Y-%m-%d")}<br/>
    <b>Hora:</b> {datetime.now().strftime("%H:%M:%S")}<br/>
    <b>Duracion monitoreo:</b> {monitoring_time}<br/>
    <b>Tipo analisis:</b> {analysis_type}<br/>
    <b>Total conexiones:</b> {len(results)}<br/>
    """
    elements.append(
        Paragraph(info, styles["BodyText"])
    )
    suspicious_count = sum(
        1
        for r in results
        if r["suspicious"] == "Si"
    )
    high_risk_count = sum(
        1
        for r in results
        if r["risk"] == "ALTO"
    )
    summary = f"""
    <b>Conexiones sospechosas:</b> {suspicious_count}<br/>
    <b>Conexiones de alto riesgo:</b> {high_risk_count}<br/>
    """
    elements.append(
        Paragraph(summary, styles["BodyText"])
    )
    elements.append(Spacer(1, 20))
    if analysis_type == "BASICO":
        data = [[
            "IP Origen",
            "IP Destino",
            "Puerto",
            "Protocolo",
            "Sospechosa"
        ]]
    else:
        data = [[
            "IP Origen",
            "IP Destino",
            "Puerto",
            "Protocolo",
            "Pais",
            "Maliciosa",
            "Trafico anomalo",
            "Conexiones",
            "Destinos",
            "Riesgo",
            "Sospechosa"
        ]]
    for result in results:

        if analysis_type == "BASICO":
            data.append([
                result["src_ip"],
                result["dst_ip"],
                str(result["port"]),
                result["protocol"],
                result["suspicious"]
            ])
        else:
            data.append([
                result["src_ip"],
                result["dst_ip"],
                str(result["port"]),
                result["protocol"],
                result["country"],
                result["malicious"],
                result["anomalous_traffic"],
                str(result["packet_count"]),
                str(result["unique_destinations"]),
                result["risk"],
                result["suspicious"]
            ])
    table = Table(data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 7),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    elements.append(table)
    document.build(elements)
    print(f"\nReporte generado: {filename}")

def export_dns_report_pdf(results):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = (
        f"{REPORT_FOLDER}/"
        f"AnalisisDNS_{timestamp}.pdf")
    document = SimpleDocTemplate(
        filename,
        pagesize=letter)

    styles = getSampleStyleSheet()
    elements = []

    title = Paragraph(
        "Reporte analisis DNS",
        styles["Title"])
    elements.append(title)
    elements.append(Spacer(1, 20))

    info_text = f"""
    <b>Fecha:</b> {datetime.now().strftime("%Y-%m-%d")}<br/>
    <b>Hora:</b> {datetime.now().strftime("%H:%M:%S")}<br/>
    """
    elements.append(Paragraph(info_text,styles["BodyText"]))
    elements.append(Spacer(1, 20))

    data = [[
        "Tipo",
        "Valor",
        "Resultado",
        "IP Maliciosa",
        "Dominio Sospechoso"
    ]]
    for result in results:
        data.append([
            result["type"],
            result["value"],
            result["resolved"],
            result["ip_malicious"],
            result["suspicious"]
        ])

    table = Table(
        data,
        colWidths=[
            50,
            100,
            200,
            70,
            90
        ]
    )
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige)
    ]))
    elements.append(table)
    document.build(elements)

    print(f"\nReporte generado: {filename}")

def export_risk_report_pdf(
    risk_score,
    risk_level,
    vulnerabilities,
    top5
):
    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )
    filename = (
        f"{REPORT_FOLDER}/"
        f"AnalisisRiesgo_{timestamp}.pdf"
    )
    document = SimpleDocTemplate(
        filename,
        pagesize=letter
    )
    styles = getSampleStyleSheet()
    elements = []

    title = Paragraph(
        "Reporte de riesgos",
        styles["Title"]
    )
    elements.append(title)
    elements.append(
        Spacer(1,20)
    )
    critical_count = sum(
        1
        for v in vulnerabilities
        if v["severity"] == "CRITICAL"
    )
    high_count = sum(
        1
        for v in vulnerabilities
        if v["severity"] == "HIGH"
    )
    medium_count = sum(
        1
        for v in vulnerabilities
        if v["severity"] == "MEDIUM"
    )
    low_count = sum(
        1
        for v in vulnerabilities
        if v["severity"] == "LOW"
    )
    summary = f"""
    <b>Fecha:</b>
    {datetime.now().strftime("%Y-%m-%d")}<br/>
    <b>Hora:</b>
    {datetime.now().strftime("%H:%M:%S")}<br/>
    <b>Riesgo General:</b>
    {risk_score}/10<br/>
    <b>Nivel de Riesgo:</b>
    {risk_level}<br/>
    <b>Total Vulnerabilidades:</b>
    {len(vulnerabilities)}<br/>
    <b>Criticas:</b>
    {critical_count}<br/>
    <b>Altas:</b>
    {high_count}<br/>
    <b>Medias:</b>
    {medium_count}<br/>
    <b>Bajas:</b>
    {low_count}<br/>

    """
    elements.append(
        Paragraph(
            summary,
            styles["BodyText"]
        )
    )
    elements.append(
        Spacer(1,20)
    )
    graph_files = [
        "riesgo_general.png",
        "severidades.png",
        "matriz_riesgos.png"
    ]
    for graph in graph_files:
        graph_path = (
            f"{GRAPHICS_FOLDER}/"
            f"{graph}"
        )
        if os.path.isfile(
            graph_path
        ):
            elements.append(
                Image(
                    graph_path,
                    width=400,
                    height=250
                )
            )
            elements.append(
                Spacer(1,15)
            )
    subtitle = Paragraph(
        "Top 5 vulnerabilidades por impacto",
        styles["Heading2"]
    )
    elements.append(subtitle)
    elements.append(
        Spacer(1,10)
    )
    table_data = [[
        "CVE",
        "Severidad",
        "CVSS",
        "Impacto",
        "Servicio",
        "Puerto"
    ]]
    for vuln in top5:
        table_data.append([
            vuln["cve"],
            vuln["severity"],
            str(vuln["score"]),
            str(vuln["impact"]),
            vuln["service"],
            str(vuln["port"])
        ])
    table = Table(
        table_data,
        colWidths=[
            90,
            60,
            50,
            50,
            90,
            50
        ]
    )
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.grey),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('GRID', (0,0), (-1,-1), 1, colors.black),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 8)
    ]))

    elements.append(table)
    document.build(
        elements
    )
    print(
        f"\nReporte generado: "
        f"{filename}"
    )
