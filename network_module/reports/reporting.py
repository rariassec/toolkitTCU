from toolkitTCU.network_module.core.scan_results import scan_results
from toolkitTCU.network_module.core.risk_calculator import (
    calculate_global_risk,
    classify_risk,
    get_all_vulnerabilities,
    top_vulnerabilities
)
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    Image,
    PageBreak
)
from reportlab.lib.styles import (
    getSampleStyleSheet
)
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from datetime import datetime
from toolkitTCU.network_module.core.config import (
    REPORT_FOLDER,
    GRAPHICS_FOLDER
)
import os

def generate_final_report():
    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )
    filename = (
        f"{REPORT_FOLDER}/"
        f"ReporteFinal_{timestamp}.pdf"
    )
    document = SimpleDocTemplate(
        filename,
        pagesize=letter
    )
    styles = getSampleStyleSheet()
    elements = []

    elements.append(
        Paragraph(
            "Reporte final de seguridad",
            styles["Title"]
        )
    )
    elements.append(
        Spacer(1, 20)
    )
    elements.append(
        Paragraph(
            f"Fecha: {datetime.now().strftime('%Y-%m-%d')}",
            styles["BodyText"]
        )
    )
    elements.append(
        Paragraph(
            f"Hora: {datetime.now().strftime('%H:%M:%S')}",
            styles["BodyText"]
        )
    )
    elements.append(
        Spacer(1, 20)
    )
    tcp_count = len(
        scan_results["tcp"]
    )
    udp_count = len(
        scan_results["udp"]
    )
    dns_count = len(
        scan_results["dns"]
    )
    suspicious_count = len(
        scan_results["suspicious_connections"]
    )
    vulnerabilities = (
        get_all_vulnerabilities()
    )
    vuln_count = len(
        vulnerabilities
    )
    risk_score = scan_results.get(
        "risk_calculator",
        0
    )

    if risk_score == 0:
        risk_score = calculate_global_risk()

    risk_level = (
        classify_risk(
            risk_score
        )
    )
    elements.append(
        Paragraph(
            "Resumen general",
            styles["Heading1"]
        )
    )
    elements.append(
        Spacer(1, 10)
    )
    summary_data = [
        ["Indicador", "Cantidad"],
        ["Puertos TCP", tcp_count],
        ["Puertos UDP", udp_count],
        ["Vulnerabilidades", vuln_count],
        ["Conexiones sospechosas", suspicious_count],
        ["Registros DNS", dns_count],
        ["Nivel de riesgo", risk_level]
    ]
    summary_table = Table(
        summary_data,
        colWidths=[250, 150]
    )
    summary_table.setStyle(
        TableStyle([
            ('BACKGROUND',(0,0),(-1,0),colors.grey),
            ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
            ('GRID',(0,0),(-1,-1),1,colors.black),
            ('ALIGN',(0,0),(-1,-1),'CENTER'),
            ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold')
        ])
    )
    elements.append(
        summary_table
    )
    elements.append(
        Spacer(1,20)
    )
    elements.append(
        Paragraph(
            "Análisis Gráfico",
            styles["Heading1"]
        )
    )
    elements.append(
        Spacer(1,10)
    )
    graph_files = [
        "riesgo_general.png",
        "severidades.png",
        "matriz_riesgos.png"
    ]
    for graph in graph_files:
        graph_path = (
            f"{GRAPHICS_FOLDER}/{graph}"
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
    elements.append(
        PageBreak()
    )
    elements.append(
        Paragraph(
            "Top 5 Vulnerabilidades",
            styles["Heading1"]
        )
    )
    elements.append(
        Spacer(1,10)
    )
    top5 = (
        top_vulnerabilities()
    )

    vuln_table_data = [[
        "CVE",
        "Severidad",
        "CVSS",
        "Impacto",
        "Servicio",
        "Puerto"
    ]]
    for vuln in top5:
        vuln_table_data.append([
            vuln["cve"],
            vuln["severity"],
            str(vuln["score"]),
            str(vuln["impact"]),
            vuln["service"],
            str(vuln["port"])
        ])
    vuln_table = Table(
        vuln_table_data,
        colWidths=[
            90,
            70,
            50,
            50,
            90,
            50
        ]
    )
    vuln_table.setStyle(
        TableStyle([
            ('BACKGROUND',(0,0),(-1,0),colors.grey),
            ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
            ('GRID',(0,0),(-1,-1),1,colors.black),
            ('ALIGN',(0,0),(-1,-1),'CENTER'),
            ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
            ('FONTSIZE',(0,0),(-1,-1),8)
        ])
    )
    elements.append(
        vuln_table
    )
    elements.append(
        Spacer(1,20)
    )

    elements.append(
        Paragraph(
            "Top 5 conexiones de alto riesgo",
            styles["Heading1"]
        )
    )
    elements.append(
        Spacer(1,10)
    )
    high_risk_connections = []
    for conn in scan_results[
        "suspicious_connections"
    ]:
        if (
            conn.get("risk")
            == "ALTO"
        ):
            high_risk_connections.append(
                conn
            )
    high_risk_connections = (
        high_risk_connections[:5]
    )
    connection_data = [[
        "IP Origen",
        "IP Destino",
        "Puerto",
        "País",
        "Riesgo"
    ]]

    for conn in high_risk_connections:
        connection_data.append([
            conn.get(
                "src_ip",
                "N/A"
            ),
            conn.get(
                "dst_ip",
                "N/A"
            ),
            str(
                conn.get(
                    "port",
                    "N/A"
                )
            ),
            conn.get(
                "country",
                "N/A"
            ),
            conn.get(
                "risk",
                "N/A"
            )
        ])
    connection_table = Table(
        connection_data,
        colWidths=[
            100,
            100,
            60,
            80,
            60
        ]
    )
    connection_table.setStyle(
        TableStyle([
            ('BACKGROUND',(0,0),(-1,0),colors.grey),
            ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
            ('GRID',(0,0),(-1,-1),1,colors.black),
            ('ALIGN',(0,0),(-1,-1),'CENTER'),
            ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
            ('FONTSIZE',(0,0),(-1,-1),8)
        ])
    )
    elements.append(
        connection_table
    )
    elements.append(
        Spacer(1,20)
    )

    elements.append(
        Paragraph(
            f"Nivel de riesgo calculado: {risk_score}/10",
            styles["Heading2"]
        )
    )

    elements.append(
        Paragraph(
            "Conclusión",
            styles["Heading1"]
        )
    )
    elements.append(
        Spacer(1,10)
    )
    if risk_score >= 9:
        conclusion = (
            "La infraestructura presenta "
            "un nivel CRÍTICO de riesgo. "
            "Se recomienda aplicar medidas "
            "correctivas inmediatas."
        )
    elif risk_score >= 7:
        conclusion = (
            "Se identificaron "
            "vulnerabilidades de alto impacto "
            "que requieren atención."
        )
    elif risk_score >= 4:
        conclusion = (
            "La infraestructura presenta "
            "un nivel moderado de exposición. "
            "Se recomienda fortalecer "
            "las medidas preventivas."
        )
    else:
        conclusion = (
            "La infraestructura presenta "
            "un nivel de riesgo bajo y "
            "mantiene una postura de "
            "seguridad aceptable."
        )
    elements.append(
        Paragraph(
            conclusion,
            styles["BodyText"]
        )
    )

    document.build(
        elements
    )

    print(
        f"\nReporte ejecutivo generado: "
        f"{filename}"
    )
def reporting_menu():

    print("\n============================================================")
    print(" REPORTERIA")
    print("============================================================")
    print("Genera el reporte de red con los analisis realizados en esta")
    print("sesion (escaneos, vulnerabilidades, dns y conexiones)")
    print("Los reportes se guardan en la carpeta reportes del toolkit")
    print()

    generate_final_report()

    try:
        from toolkitTCU.integration import network_facade
        from toolkitTCU.common.reports import save_module_report
        result = network_facade.build_module_result()
        json_path, pdf_path = save_module_report(
            result, "reporte_red", "Reporte de Análisis de Red"
        )
        print(f"\n[+] Reporte de red guardado:")
        print(f"    JSON: {json_path}")
        print(f"    PDF : {pdf_path}")
    except Exception as error:
        print(f"\n[-] No se pudo guardar el reporte normalizado de red: {error}")
