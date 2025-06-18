from typing import Dict, List
from .models.scan_result import TechInfo

def detect_tech_from_headers(headers: Dict[str, str]) -> TechInfo:
    """Detect technologies from HTTP headers"""
    tech = TechInfo(
        server=headers.get("Server", ""),
        x_powered_by=headers.get("X-Powered-By", "")
    )
    return tech

def detect_tech_from_content(content: str, headers: Dict[str, str]) -> TechInfo:
    """Detect technologies from page content"""
    tech = detect_tech_from_headers(headers)
    content_lower = content.lower()
    
    # CMS Detection
    if "wp-content" in content_lower:
        tech.cms = "WordPress"
    elif "/joomla/" in content_lower:
        tech.cms = "Joomla"
    elif "/drupal/" in content_lower:
        tech.cms = "Drupal"
    
    # Framework Detection
    if "/static/" in content or "react" in content_lower:
        tech.framework = "React/SPA"
    elif "laravel" in content_lower:
        tech.framework = "Laravel"
    elif "django" in content_lower:
        tech.framework = "Django"
    
    # Language Detection
    if ".php" in content_lower:
        tech.languages.append("PHP")
    if ".aspx" in content_lower:
        tech.languages.append("ASP.NET")
    if "node.js" in content_lower:
        tech.languages.append("Node.js")
    
    # Cookies
    cookies = headers.get("Set-Cookie", "")
    if "PHPSESSID" in cookies:
        tech.languages.append("PHP")
    if "JSESSIONID" in cookies:
        tech.languages.append("Java")
    
    return tech