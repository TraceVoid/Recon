from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict

@dataclass
class TechInfo:
    server: str = ""
    x_powered_by: str = ""
    framework: str = "Desconocido"
    cms: str = "Desconocido"
    languages: List[str] = field(default_factory=list)

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
    tech_info: 'TechInfo'
    vulnerabilities: 'VulnerabilityResults'

    content: str = ""
    nuclei_findings: List[Dict] = field(default_factory=list)
    common_files: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    phones: List[str] = field(default_factory=list)
    interesting_file: bool = False
    timestamp: str = datetime.now().isoformat()

    @property
    def is_interesting(self) -> bool:
        return (
            self.vulnerabilities.xss or
            self.vulnerabilities.sqli or
            self.vulnerabilities.open_redirect or
            self.common_files or
            (self.nuclei_findings and len(self.nuclei_findings) > 0)
        )

