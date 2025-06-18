import requests
from urllib.parse import urljoin, urlparse
from typing import List, Optional
from ..config import HEADERS, REQUEST_TIMEOUT

def is_valid_url(url: str, base_url: str) -> bool:
    """Check if URL belongs to the same domain"""
    parsed_base = urlparse(base_url)
    parsed = urlparse(url)
    return (parsed.netloc == parsed_base.netloc or not parsed.netloc) and \
           parsed.scheme in ['http', 'https']

def fetch_url(url: str) -> Optional[requests.Response]:
    """Fetch URL with custom headers and timeout"""
    try:
        return requests.get(
            url, 
            headers=HEADERS, 
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True
        )
    except requests.RequestException:
        return None

def join_urls(base: str, relative: str) -> str:
    """Safely join URLs"""
    return urljoin(base, relative)