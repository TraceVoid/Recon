import os
from pathlib import Path

# Configuración de paths
BASE_DIR = Path(__file__).parent.parent
SCAN_DIR = BASE_DIR / "scans"

# Configuración de requests
REQUEST_TIMEOUT = 10
MAX_REDIRECTS = 5
THREAD_TIMEOUT = 30

# Headers personalizados
HEADERS = {
    "User-Agent": "Mozilla/5.0 (SpiderBot)",
    "Accept": "text/html,application/xhtml+xml",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive"
}

# Listas de elementos interesantes
INTERESTING_EXTENSIONS = [
    ".zip", ".sql", ".env", ".php", ".js", ".bak", ".log", ".txt", 
    ".conf", ".git", ".tar", ".gz", ".rar", ".7z", ".csv", ".xls", 
    ".xlsx", ".doc", ".docx", ".pdf", ".pem", ".key", ".ppk"
]

COMMON_FILES = [
    "robots.txt", "sitemap.xml", ".git/HEAD", ".env", 
    "admin", "wp-admin", "config.php", "backup.zip"
]

# Payloads para pruebas
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "javascript:alert(1)"
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--"
]

def setup_scan_dir(scan_name):
    """Create directory for scan results"""
    scan_path = SCAN_DIR / scan_name
    scan_path.mkdir(parents=True, exist_ok=True)
    return scan_path