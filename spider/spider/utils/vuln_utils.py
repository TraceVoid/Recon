import requests
from typing import Dict
from ..config import HEADERS, XSS_PAYLOADS, SQLI_PAYLOADS, REQUEST_TIMEOUT

def test_xss(url: str) -> bool:
    """Test for basic XSS vulnerabilities"""
    for payload in XSS_PAYLOADS:
        try:
            response = requests.get(
                url, 
                params={"q": payload}, 
                headers=HEADERS, 
                timeout=REQUEST_TIMEOUT
            )
            if payload in response.text:
                return True
        except requests.RequestException:
            continue
    return False

def test_sqli(url: str) -> bool:
    """Test for basic SQL injection vulnerabilities"""
    for payload in SQLI_PAYLOADS:
        try:
            response = requests.get(
                url, 
                params={"id": payload}, 
                headers=HEADERS, 
                timeout=REQUEST_TIMEOUT
            )
            if "error" in response.text.lower() or "syntax" in response.text.lower():
                return True
        except requests.RequestException:
            continue
    return False

def test_open_redirect(url: str) -> bool:
    """Test for open redirect vulnerabilities"""
    test_url = f"{url}?redirect=http://evil.com"
    try:
        response = requests.get(
            test_url, 
            headers=HEADERS, 
            allow_redirects=False,
            timeout=REQUEST_TIMEOUT
        )
        return response.status_code in [301, 302] and "evil.com" in response.headers.get("Location", "")
    except requests.RequestException:
        return False

def test_vulnerabilities(url: str) -> Dict[str, bool]:
    """Run all vulnerability tests"""
    return {
        "xss": test_xss(url),
        "sqli": test_sqli(url),
        "open_redirect": test_open_redirect(url)
    }