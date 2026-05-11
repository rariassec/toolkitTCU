import sqlite3
import hashlib  
import os
import json
from datetime import datetime

class ReportGenerator:
    
    def __init__(self, db_manager):
        self.db_manager=db_manager
    
    def generate_individual_json_report(self):
        if not os.path.exists("reports/individual"):
            os.makedirs("reports/individual")
        counter=0
        all_reports=self.db_manager.obtain_info_for_individual_json_report()
        for report in all_reports:
            report_name=f"reports/individual/report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}_{counter}.json"
            counter+=1
            with open(report_name, "w") as f:
                json.dump(report,f,indent=4)
                f.close()

    def generate_general_json_report(self):
        if not os.path.exists("reports/general"):
            os.makedirs("reports/general")
        
        general_report=self.db_manager.obtain_info_for_general_json_report()
        report_name=f"reports/general/general_report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.json"
        with open(report_name, "w") as f:
            json.dump(general_report,f,indent=4)
            f.close()
