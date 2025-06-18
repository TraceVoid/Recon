from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict, Optional

@dataclass
class TechInfo:
    server: str = ""
    x_powered_by: str = ""
    framework: str = "Desconocido"
    cms: str = "Desconocido"
    languages: List[str] = None

@dataclass
class VulnerabilityResults:
    xss: bool = False
    sqli: bool = False
    open_redirect: bool = False

@dataclass
class ScanResult:
    url: str
    depth: int
    status_code: int
    content_type: str
    content_length: int
    headers: Dict[str, str]
    tech_info: TechInfo
    vulnerabilities: VulnerabilityResults
    nuclei_findings: List[Dict] = None
    common_files: List[str] = None
    emails: List[str] = None
    phones: List[str] = None
    timestamp: str = datetime.now().isoformat()
    
    @property
    def is_interesting(self) -> bool:
        """Check if the result contains interesting findings"""
        return (self.vulnerabilities.xss or 
                self.vulnerabilities.sqli or
                self.vulnerabilities.open_redirect or
                self.common_files or
                (self.nuclei_findings and len(self.nuclei_findings) > 0))