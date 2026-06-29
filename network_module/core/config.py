
import os
from toolkitTCU.common.reports import REPORTS_DIR

HTTP_TIMEOUT = 10
MAX_CVES = 5
REPORT_FOLDER = REPORTS_DIR
GRAPHICS_FOLDER = os.path.join(REPORTS_DIR, "graficos")

def _load_vt_key():
    key = os.environ.get("VT_API_KEY", "")
    if key:
        return key
    _module_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    _creds_file = os.path.join(_module_dir, "vt_credentials.env")
    if os.path.isfile(_creds_file):
        with open(_creds_file, "r") as _f:
            for _line in _f:
                _line = _line.strip()
                if _line.startswith("VT_API_KEY="):
                    _k = _line.split("=", 1)[1].strip()
                    if _k:
                        os.environ["VT_API_KEY"] = _k
                        return _k
    return ""

VT_API_KEY = _load_vt_key()
VT_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

def _load_nvd_key():
    key = os.environ.get("NVD_API_KEY", "")
    if key:
        return key
    _module_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    _creds_file = os.path.join(_module_dir, "nvd_credentials.env")
    if os.path.isfile(_creds_file):
        with open(_creds_file, "r") as _f:
            for _line in _f:
                _line = _line.strip()
                if _line.startswith("NVD_API_KEY="):
                    _k = _line.split("=", 1)[1].strip()
                    if _k:
                        os.environ["NVD_API_KEY"] = _k
                        return _k
    return ""

NVD_API_KEY = _load_nvd_key()
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
def nvd_interval_for_key(has_key):
    return 0.8 if has_key else 6.5

NVD_REQUEST_INTERVAL = nvd_interval_for_key(bool(NVD_API_KEY))
NVD_MAX_RETRIES = 3
NVD_RETRY_BACKOFF = 4

DETECTION_DURATION_OPTIONS = {
    "1": 60,
    "2": 300,
    "3": -1
}
SENSITIVITY_LEVELS = {
    "1": "BASICO",
    "2": "AVANZADO"
}
ANOMALOUS_PACKET_THRESHOLD = 200

SUSPICIOUS_PORTS = [
    4444,
    23,
    445,
    3389,
    5900,
    5555,
    6666,
    1337,
    31337
]
HIGH_RISK_COUNTRIES = [
    "RU",
    "KP",
    "IR",
    "CN",
    "BY",
    "SY"
]
DESTINATION_THRESHOLD = 30
DNS_PORTS = [
    53,
    853
]
CRITICAL_SERVICES = [

    "microsoft-ds",
    "netbios-ssn",
    "ssh",
    "rdp",
    "ms-wbt-server",
    "http",
    "https",
    "ftp",
    "telnet",
    "mysql",
    "postgresql",
    "mssql"

]
CRITICAL_VULNERABILITY_BONUS = 3
HIGH_VULNERABILITY_BONUS = 2
EXPOSED_SERVICE_BONUS = 2
