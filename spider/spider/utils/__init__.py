"""
Utilidades para el spider (redes, vulnerabilidades, archivos, etc.)
"""

from .network_utils import *
from .vuln_utils import *
from .file_utils import *
from .tech_detector import *
from .dns_utils import *

__all__ = [
    'is_valid_url',
    'fetch_url',
    'test_xss',
    'test_sqli',
    'extract_emails',
    'detect_tech_from_headers'
    # Añade aquí todas las funciones que quieras exportar
]
