import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from datetime import datetime, timedelta
from toolkitTCU.integrity_module.core import DatabaseManager
from toolkitTCU.integrity_module.utils.LoadConfig import MODULE_DIR
import os
import traceback

class Stats:
    def __init__(self, db_manager: DatabaseManager):
        plt.style.use('seaborn-v0_8-darkgrid')
        self.db_manager = db_manager

    def _save_graph(self, prefix):
        folder = os.path.join(MODULE_DIR, "reports", "general")
        os.makedirs(folder, exist_ok=True)
        path = os.path.join(folder, f"{prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.png")
        plt.savefig(path, dpi=150)
        plt.close()
        print(f"[+] Grafico guardado en: {path}")
        return path

    def get_monitored_files(self):
        return self.db_manager.get_total_files_monitored()

    def get_last_scan_date_and_time(self):
        return self.db_manager.get_last_scan_session()

    def get_detected_changes(self):
        return self.db_manager.get_detected_changes()

    def get_avg_scan_time(self):
        return self.db_manager.get_avg_scan_time()

    def get_system_state(self):
        changes_detected = self.db_manager.get_detected_changes()
        return "Alerta" if changes_detected else "Seguro"

    def changes_last_7_days_graph(self, save_path=None):
        try:
            events_7_map = self.db_manager.get_changes_last_7_days()
            days = []
            changes = []
            now = datetime.now()
            for i in range(6, -1, -1):
                fecha = (now - timedelta(days=i))
                date_key = fecha.strftime('%d/%m')
                days.append(date_key)
                changes.append(events_7_map.get(date_key, 0))

            days = days[::-1]
            changes = changes[::-1]

            fig, ax = plt.subplots(figsize=(8, 4))
            bars = ax.barh(days, changes, color='#2E86AB', edgecolor='#1B4965', height=0.6)

            for i, (bar, valor) in enumerate(zip(bars, changes)):
                if valor > 0:
                    ax.text(valor + 0.1, bar.get_y() + bar.get_height()/2,
                            str(valor), va='center', ha='left', fontsize=10, fontweight='bold')

            ax.set_title('Tendencia de cambios (Ultimos 7 dias)', fontsize=14, fontweight='bold')
            ax.set_xlabel('Numero de cambios', fontsize=11)
            ax.set_xlim(0, max(changes) + 1 if max(changes) > 0 else 3)

            ax.grid(axis='x', linestyle='--', alpha=0.3)
            ax.spines['top'].set_visible(False)
            ax.spines['right'].set_visible(False)

            plt.tight_layout()
            if save_path:
                plt.savefig(save_path, dpi=150)
                plt.close()
            else:
                self._save_graph("estadistica")
        except Exception as e:
            print(f"Error al generar grafico de 7 dias: {e}")
            print(traceback.format_exc())

    def afected_files_extensions_graph(self, save_path=None):
        try:
            extensions = {}
            files = self.db_manager.get_all_files_from_changes()
            if not files:
                return
            for file in files:
                file_extension = os.path.splitext(file)[1].lower()
                if file_extension in extensions.keys():
                    extensions[file_extension] += 1
                else:
                    if file_extension == "":
                        file_extension = "Sin ext"
                    extensions[file_extension] = 1

            sorted_items = sorted(extensions.items(), key=lambda x: x[1], reverse=True)
            ext_labels = [item[0] for item in sorted_items]
            count = [item[1] for item in sorted_items]
            total = sum(count)
            porcentages = [round((x / total) * 100, 1) for x in count]

            fig, ax = plt.subplots(figsize=(8, 4))
            bars = ax.barh(ext_labels, porcentages, color='#2E86AB', edgecolor='#1B4965', height=0.6)

            for i, (bar, valor) in enumerate(zip(bars, porcentages)):
                if valor > 0:
                    ax.text(valor + 0.1, bar.get_y() + bar.get_height()/2,
                            str(valor), va='center', ha='left', fontsize=10, fontweight='bold')

            ax.set_title('Tipos de archivo afectados', fontsize=14, fontweight='bold')
            ax.set_xlabel('Porcentajes', fontsize=11)
            ax.set_xlim(0, max(porcentages) + 1 if max(porcentages) > 0 else 3)

            ax.grid(axis='x', linestyle='--', alpha=0.3)
            ax.spines['top'].set_visible(False)
            ax.spines['right'].set_visible(False)

            plt.tight_layout()
            if save_path:
                plt.savefig(save_path, dpi=150)
                plt.close()
            else:
                self._save_graph("estadistica")
        except Exception as e:
            print(f"Error al generar grafico de extensiones: {e}")
            print(traceback.format_exc())

    def tendency_30d_graph(self, save_path=None):
        try:
            all_events_per_day = self.db_manager.get_all_events_per_day()
            fig, ax = plt.subplots(figsize=(12, 4))
            dates = []
            values = []
            now = datetime.now()
            for i in range(30, -1, -1):
                d = (now - timedelta(days=i))
                date_key = d.strftime('%Y-%m-%d')
                dates.append(date_key)
                values.append(all_events_per_day.get(date_key, 0))

            ax.fill_between(dates, values, alpha=0.3, color='#6c757d')
            ax.plot(dates, values, marker='o', linewidth=2, color='#2E86AB')

            ax.set_facecolor('#f8f9fa')
            ax.grid(True, linestyle='--', alpha=0.5)
            ax.set_xlabel('Fecha', fontsize=10)
            ax.set_ylabel('Cambios detectados', fontsize=10)
            ax.set_title('TENDENCIA DE CAMBIOS - ULTIMOS 30 DIAS',
                        fontsize=12, fontweight='bold', pad=15)

            ax.xaxis.set_major_formatter(mdates.DateFormatter('%d/%m'))
            plt.xticks(rotation=45)

            plt.tight_layout()
            if save_path:
                plt.savefig(save_path, dpi=150)
                plt.close()
            else:
                self._save_graph("estadistica")
                plt.close()
        except Exception as e:
            print(f"Error al generar grafico de 30 dias: {e}")
            print(traceback.format_exc())

    def display_events_table(self):
        try:
            events = self.db_manager.get_detected_events()
            if not events:
                print("\n[+] No hay eventos detectados\n")
                return

            print("╔" + "═" * 95 + "╗")
            print(f"║{ 'HISTORIAL DE EVENTOS RECIENTES' :^95}║")
            print("╠" + "═" * 4 + "╦" + "═" * 14 + "╦" + "═" * 21 + "╦" + "═" * 14 + "╦" + "═" * 38 + "╣")
            print(f"║ { ' #' :<2} ║ { 'Tipo' :<12} ║ { 'Fecha/Hora' :<19} ║ { 'Hash' :<12} ║ { 'Ruta' :<36} ║")
            print("╠" + "═" * 4 + "╬" + "═" * 14 + "╬" + "═" * 21 + "╬" + "═" * 14 + "╬" + "═" * 38 + "╣")

            for i, ev in enumerate(events, 1):
                tipo = ev.get("event_type", "N/A")[:12]
                fecha = ev.get("time", "N/A")[:19]
                h_short = ev.get("hash_short", "N/A")[:12]
                ruta = ev.get("path", "N/A")
                if len(ruta) > 36:
                    ruta = "..." + ruta[-33:]
                print(f"║ {i:<2} ║ {tipo:<12} ║ {fecha:<19} ║ {h_short:<12} ║ {ruta:<36} ║")

            print("╚" + "═" * 4 + "╩" + "═" * 14 + "╩" + "═" * 21 + "╩" + "═" * 14 + "╩" + "═" * 38 + "╝")
        except Exception as e:
            print(f"Error al mostrar tabla de eventos: {e}")
            print(traceback.format_exc())
