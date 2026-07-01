import sqlite3
import os
import json
import traceback
from datetime import datetime
from toolkitTCU.integrity_module.core.DatabaseManager import DatabaseManager, DB_PATH
from toolkitTCU.integrity_module.utils.Logger import Logger
from toolkitTCU.integrity_module.utils.LoadConfig import ConfigLoader
from toolkitTCU.integrity_module.core.stats import Stats
from toolkitTCU.common.reports import REPORTS_DIR

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

class ReportGenerator:

    def __init__(self, db_manager: DatabaseManager, log: Logger, load_config:ConfigLoader, stats:Stats):
        self.db_manager=db_manager
        self.log=log
        self.general_directory = REPORTS_DIR
        self.individual_directory = REPORTS_DIR
        self.stats=stats

    def generate_individual_json_report(self):
        try:
            if not os.path.exists(self.individual_directory):
                os.makedirs(self.individual_directory, exist_ok=True)
            counter=0
            all_reports=self.db_manager.obtain_info_for_individual_report()
            if not all_reports:
                self.log.add_to_log("EXCEPTION", "WARNING", "REPORTES INDIVIDUALES | Sin eventos disponibles")
                return
            for report in all_reports:
                report_name=f"{self.individual_directory}/report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}_{counter}.json"
                counter+=1
                with open(report_name, "w") as f:
                    json.dump(report,f,indent=4)
                    f.close()
            self.log.add_to_log("SYSTEM", "INFO", f"REPORTES INDIVIDUALES GENERADOS | Cantidad: {counter} | Ruta: {self.individual_directory}/")
            return True
        except Exception as e:
             print(f"Error en generate_individual_json_report: {e}")
             print(traceback.format_exc())
             self.log.add_to_log("EXCEPTION", "ERROR", f"REPORTES INDIVIDUALES fallo | Error: {e}")
             return False

    def generate_general_json_report(self):
        try:

            if not os.path.exists(self.general_directory):
                os.makedirs(self.general_directory, exist_ok=True)

            general_report=self.db_manager.obtain_info_for_general_report()
            if not general_report:
                self.log.add_to_log("EXCEPTION", "WARNING", "REPORTE GENERAL | Sin eventos disponibles")

            report_name=f"{self.general_directory}/general_report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.json"
            with open(report_name, "w") as f:
                json.dump(general_report,f,indent=4)
                f.close()
                self.log.add_to_log("SYSTEM", "INFO", f"REPORTE GENERAL GENERADO | Eventos: {len(general_report)} | Archivo: {report_name}")
                return True
        except Exception as e:
            print(f"Error en generate_general_json_report: {e}")
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"REPORTE GENERAL fallo | Error: {e}")
            return False

    def generate_general_txt_report(self):
        try:

            if not os.path.exists(self.general_directory):
                os.makedirs(self.general_directory, exist_ok=True)

            general_report=self.db_manager.obtain_info_for_general_report()
            if not general_report:
                self.log.add_to_log("EXCEPTION", "WARNING", "REPORTE GENERAL | Sin eventos disponibles")

            report_name=f"{self.general_directory}/general_report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
            with open(report_name, "w") as f:
                for report in general_report:
                    for key, value in report.items():
                        f.write(f"{key}: {value}\n")
                    self.log.add_to_log("SYSTEM", "INFO", f"REPORTE GENERAL GENERADO | Eventos: {len(general_report)} | Archivo: {report_name}")
                return True
        except Exception as e:
            print(f"Error en generate_general_txt_report: {e}")
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"REPORTE GENERAL fallo | Error: {e}")
            return False

    def generate_individual_txt_report(self):
        try:
            if not os.path.exists(self.individual_directory):
                os.makedirs(self.individual_directory, exist_ok=True)
            counter=0
            all_reports=self.db_manager.obtain_info_for_individual_report()
            if not all_reports:
                self.log.add_to_log("EXCEPTION", "WARNING", "REPORTES INDIVIDUALES | Sin eventos disponibles")
                return
            for report in all_reports:
                report_name=f"{self.individual_directory}/report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}_{counter}.txt"
                counter+=1
                with open(report_name, "w") as f:
                    for key, value in report.items():
                        f.write(f"{key}: {value}\n")
            self.log.add_to_log("SYSTEM", "INFO", f"REPORTES INDIVIDUALES GENERADOS | Cantidad: {counter} | Ruta: {self.individual_directory}/")
            return True
        except Exception as e:
             print(f"Error en generate_individual_txt_report: {e}")
             print(traceback.format_exc())
             self.log.add_to_log("EXCEPTION", "ERROR", f"REPORTES INDIVIDUALES fallo | Error: {e}")
             return False

    def generate_executive_summary(self):

        try:
            total_monitored = self.stats.get_monitored_files()
            last_scan_date, last_scan_time = self.stats.get_last_scan_date_and_time()
            changes_detected = self.stats.get_detected_changes()
            avg_scan_time = self.stats.get_avg_scan_time()

            algo = self.db_manager.loaded_config.get("default_hashing_algorithm", "sha256").upper()

            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT event_type, COUNT(*) FROM integrity_events GROUP BY event_type")
            counts = {row['event_type']: row['COUNT(*)'] for row in c.fetchall() if row['event_type']}

            creados = counts.get("CREATED", 0)
            modificados = counts.get("MODIFIED", 0)
            eliminados = counts.get("DELETED", 0)
            actualizados = counts.get("UPDATED", 0)
            respaldos = counts.get("BACKUP", 0)
            verificados = counts.get("VERIFIED", 0)
            total_eventos = sum(counts.values())

            c.execute("SELECT COUNT(*) FROM backup_files")
            total_backups = c.fetchone()[0]

            c.execute("SELECT event_id, event_type, severity, timestamp, file_path FROM integrity_events WHERE severity IN ('CRITICAL', 'HIGH', 'MEDIUM') ORDER BY timestamp DESC LIMIT 5")
            alert_rows = c.fetchall()
            conn.close()
        except Exception as e:
            print(f"Error al obtener datos en generate_executive_summary: {e}")
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"RESUMEN EJECUTIVO fallo al obtener datos | Error: {e}")
            print(f"\033[91mError al generar resumen ejecutivo: {e}\033[0m")
            return False

        temp_dir = os.path.join(self.general_directory, "temp_plots")
        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir)

        plot_7d = os.path.join(temp_dir, "temp_7d.png")
        plot_ext = os.path.join(temp_dir, "temp_ext.png")
        plot_30d = os.path.join(temp_dir, "temp_30d.png")

        try:
            self.stats.changes_last_7_days_graph(save_path=plot_7d)
            self.stats.afected_files_extensions_graph(save_path=plot_ext)
            self.stats.tendency_30d_graph(save_path=plot_30d)
        except Exception as e:
            self.log.add_to_log("EXCEPTION", "ERROR", f"Exportacion de graficos a PNG fallo | Error: {e}")
            print(f"Advertencia: No se pudieron exportar algunos graficos. Se omitiran en el PDF. Error: {e}")

        if not os.path.exists(self.general_directory):
            os.makedirs(self.general_directory, exist_ok=True)
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        pdf_path = f"{self.general_directory}/resumen_ejecutivo_{timestamp}.pdf"

        try:

            doc = SimpleDocTemplate(
                pdf_path,
                pagesize=letter,
                rightMargin=40, leftMargin=40,
                topMargin=40, bottomMargin=40
            )

            styles = getSampleStyleSheet()

            title_style = ParagraphStyle(
                'DocTitle',
                parent=styles['Heading1'],
                fontName='Helvetica-Bold',
                fontSize=20,
                textColor=colors.HexColor('#1A365D'),
                alignment=1,
                spaceAfter=5
            )

            subtitle_style = ParagraphStyle(
                'DocSubTitle',
                parent=styles['Normal'],
                fontName='Helvetica',
                fontSize=11,
                textColor=colors.HexColor('#4A5568'),
                alignment=1,
                spaceAfter=15
            )

            section_heading = ParagraphStyle(
                'SectionHeading',
                parent=styles['Heading2'],
                fontName='Helvetica-Bold',
                fontSize=13,
                textColor=colors.HexColor('#2B6CB0'),
                spaceBefore=12,
                spaceAfter=8
            )

            body_style = ParagraphStyle(
                'BodyTextCustom',
                parent=styles['Normal'],
                fontName='Helvetica',
                fontSize=10,
                textColor=colors.HexColor('#2D3748'),
                leading=13
            )

            bold_label = ParagraphStyle(
                'BoldLabel',
                parent=body_style,
                fontName='Helvetica-Bold'
            )

            story = []

            story.append(Paragraph("MÓDULO DE INTEGRIDAD - TOOLKIT TCU", subtitle_style))
            story.append(Paragraph("RESUMEN EJECUTIVO DE SEGURIDAD", title_style))

            now_str = datetime.now().strftime('%d/%m/%Y a las %H:%M:%S')
            meta_text = f"<b>Fecha de Reporte:</b> {now_str} &nbsp;|&nbsp; <b>Último Escaneo:</b> {last_scan_date} a las {last_scan_time}"
            story.append(Paragraph(meta_text, subtitle_style))
            story.append(Spacer(1, 10))

            story.append(Paragraph("1. Estado General del Sistema", section_heading))
            general_data = [
                [Paragraph("Total de archivos bajo monitoreo", bold_label), Paragraph(str(total_monitored), body_style)],
                [Paragraph("Cambios detectados sin resolver", bold_label), Paragraph(str(changes_detected), body_style)],
                [Paragraph("Tiempo promedio de escaneo", bold_label), Paragraph(f"{avg_scan_time:.4f} segs", body_style)],
                [Paragraph("Algoritmo de Hashing en Baseline", bold_label), Paragraph(algo, body_style)]
            ]
            t1 = Table(general_data, colWidths=[240, 280])
            t1.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F7FAFC')),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('BOTTOMPADDING', (0,0), (-1,-1), 6),
                ('TOPPADDING', (0,0), (-1,-1), 6),
                ('LEFTPADDING', (0,0), (-1,-1), 10),
                ('RIGHTPADDING', (0,0), (-1,-1), 10),
                ('LINEBELOW', (0,0), (-1,-2), 0.5, colors.HexColor('#E2E8F0')),
                ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#CBD5E0'))
            ]))
            story.append(t1)
            story.append(Spacer(1, 15))

            story.append(Paragraph("2. Métricas Históricas de Eventos", section_heading))
            metrics_data = [
                [Paragraph("<b>Evento</b>", bold_label), Paragraph("<b>Cantidad</b>", bold_label)],
                [Paragraph("Creaciones (CREATED)", body_style), Paragraph(str(creados), body_style)],
                [Paragraph("Modificaciones (MODIFIED)", body_style), Paragraph(str(modificados), body_style)],
                [Paragraph("Eliminaciones (DELETED)", body_style), Paragraph(str(eliminados), body_style)],
                [Paragraph("Actualizaciones (UPDATED)", body_style), Paragraph(str(actualizados), body_style)],
                [Paragraph("Respaldos de Seguridad (BACKUP)", body_style), Paragraph(str(respaldos), body_style)],
                [Paragraph("Verificaciones de Baseline (VERIFIED)", body_style), Paragraph(str(verificados), body_style)],
                [Paragraph("<b>Total Histórico de Eventos</b>", bold_label), Paragraph(f"<b>{total_eventos}</b>", bold_label)]
            ]
            t2 = Table(metrics_data, colWidths=[240, 280])
            t2.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#E2E8F0')),
                ('BACKGROUND', (0,-1), (-1,-1), colors.HexColor('#EDF2F7')),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('BOTTOMPADDING', (0,0), (-1,-1), 5),
                ('TOPPADDING', (0,0), (-1,-1), 5),
                ('LEFTPADDING', (0,0), (-1,-1), 10),
                ('LINEBELOW', (0,0), (-1,-2), 0.5, colors.HexColor('#E2E8F0')),
                ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#CBD5E0'))
            ]))
            story.append(t2)
            story.append(Spacer(1, 15))

            story.append(Paragraph("3. Análisis de Integridad y Alerta", section_heading))
            tasa_cambio = (changes_detected / total_monitored * 100) if total_monitored else 0.0

            estado_salud = "SEGURO"
            status_color_hex = '#48BB78'
            if changes_detected > 0:
                estado_salud = "ADVERTENCIA (Cambios sin validar)"
                status_color_hex = '#ECC94B'
            if any(r['severity'] in ['CRITICAL', 'HIGH'] for r in alert_rows):
                estado_salud = "CRÍTICO (Amenaza de seguridad detectada)"
                status_color_hex = '#F56565'

            risk_data = [
                [Paragraph("Tasa actual de alteración", bold_label), Paragraph(f"{tasa_cambio:.2f}% de la base de datos", body_style)],
                [Paragraph("Nivel de alerta global", bold_label), Paragraph(f"<font color='{status_color_hex}'><b>{estado_salud}</b></font>", body_style)]
            ]
            t3 = Table(risk_data, colWidths=[240, 280])
            t3.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F7FAFC')),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('BOTTOMPADDING', (0,0), (-1,-1), 6),
                ('TOPPADDING', (0,0), (-1,-1), 6),
                ('LEFTPADDING', (0,0), (-1,-1), 10),
                ('LINEBELOW', (0,0), (-1,-2), 0.5, colors.HexColor('#E2E8F0')),
                ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#CBD5E0'))
            ]))
            story.append(t3)
            story.append(Spacer(1, 15))

            story.append(Paragraph("4. Alertas de Severidad Media / Alta Recientes", section_heading))
            if alert_rows:
                alerts_header = [
                    Paragraph("<b>ID</b>", bold_label),
                    Paragraph("<b>Tipo</b>", bold_label),
                    Paragraph("<b>Severidad</b>", bold_label),
                    Paragraph("<b>Fecha y Hora</b>", bold_label),
                    Paragraph("<b>Ruta del Archivo</b>", bold_label)
                ]
                alerts_table_data = [alerts_header]
                for r in alert_rows:
                    sev_str = r['severity'] if r['severity'] else "LOW"
                    s_color = '#F56565' if sev_str in ['CRITICAL', 'HIGH'] else '#ECC94B'

                    file_path_disp = r['file_path']
                    if len(file_path_disp) > 42:
                        file_path_disp = "..." + file_path_disp[-39:]

                    alerts_table_data.append([
                        Paragraph(str(r['event_id']), body_style),
                        Paragraph(r['event_type'], body_style),
                        Paragraph(f"<font color='{s_color}'><b>{sev_str}</b></font>", body_style),
                        Paragraph(r['timestamp'], body_style),
                        Paragraph(file_path_disp, body_style)
                    ])
                t4 = Table(alerts_table_data, colWidths=[35, 75, 75, 120, 215])
                t4.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#E2E8F0')),
                    ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 5),
                    ('TOPPADDING', (0,0), (-1,-1), 5),
                    ('LEFTPADDING', (0,0), (-1,-1), 5),
                    ('LINEBELOW', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
                    ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#CBD5E0'))
                ]))
                story.append(t4)
            else:
                story.append(Paragraph("No se registran incidentes de severidad Media, Alta o Crítica en el historial.", body_style))

            story.append(Spacer(1, 15))

            story.append(Paragraph("5. Recomendaciones de Seguridad", section_heading))
            recs = []

            if changes_detected > 0:
                recs.append(f"<b>Inspección de Alteraciones:</b> Se identificaron {changes_detected} archivos modificados sin conciliar. Se sugiere inspeccionar las rutas afectadas para descartar accesos no autorizados.")
            else:
                recs.append("<b>Mantenimiento de Baseline:</b> No se registran alteraciones sin validar en el último escaneo. Mantenga el baseline actual para asegurar la consistencia del monitoreo.")

            if total_eventos > 50:
                recs.append(f"<b>Optimización de Registros:</b> Se detecta un volumen alto de eventos históricos ({total_eventos}). Se recomienda realizar depuraciones periódicas de registros antiguos para optimizar el rendimiento.")
            else:
                recs.append(f"<b>Monitoreo de Eventos:</b> El historial registra {total_eventos} eventos acumulados. Continúe con el registro ordinario para facilitar auditorías futuras.")

            if tasa_cambio > 10:
                recs.append(f"<b>Auditoría de Directorios:</b> Con una tasa de cambio de integridad del {tasa_cambio:.2f}% en el baseline, se sugiere revisar las políticas de permisos de escritura de los directorios monitoreados.")
            else:
                recs.append("<b>Estabilidad del Sistema:</b> La tasa de variación es baja, lo que indica un entorno de archivos monitoreados estable.")

            recs.append(f"<b>Seguridad Criptográfica:</b> Las firmas de baseline utilizan el algoritmo {algo}. Se aconseja mantener este estándar robusto para garantizar la invulnerabilidad ante colisiones.")

            recs.append("<b>Monitoreo Preventivo:</b> Se sugiere complementar el monitoreo en tiempo real con escaneos completos programados periódicamente para auditar la integridad global.")

            for rec in recs:
                story.append(Paragraph(f"• {rec}", body_style))
                story.append(Spacer(1, 4))

            story.append(PageBreak())

            story.append(Paragraph("6. Gráficos y Tendencias", section_heading))
            story.append(Spacer(1, 10))

            if os.path.exists(plot_7d):
                story.append(Paragraph("<b>Tendencia de Cambios en los Últimos 7 Días</b>", bold_label))
                story.append(Spacer(1, 5))
                story.append(Image(plot_7d, width=420, height=210))
                story.append(Spacer(1, 20))

            if os.path.exists(plot_ext):
                story.append(Paragraph("<b>Distribución de Extensiones Afectadas</b>", bold_label))
                story.append(Spacer(1, 5))
                story.append(Image(plot_ext, width=420, height=210))
                story.append(Spacer(1, 20))

            if os.path.exists(plot_30d):
                story.append(PageBreak())
                story.append(Paragraph("<b>Historial de Tendencia de Cambios (30 Días)</b>", bold_label))
                story.append(Spacer(1, 5))
                story.append(Image(plot_30d, width=500, height=180))

            doc.build(story)

            self.log.add_to_log("SYSTEM", "INFO", f"RESUMEN EJECUTIVO PDF GENERADO | Ruta: {pdf_path}")
            print(f"\n\033[92m[+] Reporte de resumen ejecutivo PDF generado con exito:\033[0m")
            print(f"    {pdf_path}\n")

        except Exception as e:
            print(f"Error al compilar en generate_executive_summary: {e}")
            print(traceback.format_exc())
            self.log.add_to_log("EXCEPTION", "ERROR", f"RESUMEN EJECUTIVO PDF fallo al compilar | Error: {e}")
            print(f"\033[91mError al compilar archivo PDF de reporte: {e}\033[0m")
            return False
        finally:
            for p in [plot_7d, plot_ext, plot_30d]:
                if os.path.exists(p):
                    try:
                        os.remove(p)
                    except Exception:
                        pass
            if os.path.exists(temp_dir):
                try:
                    os.rmdir(temp_dir)
                except Exception:
                    pass

        return True
