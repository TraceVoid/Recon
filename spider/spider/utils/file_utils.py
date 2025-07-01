import re
from typing import List
from urllib.parse import urljoin
from bs4 import BeautifulSoup

def extract_emails(text: str) -> List[str]:
    """Extract emails from text"""
    email_regex = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    return list(set(re.findall(email_regex, text)))

def extract_phones(text: str) -> List[str]:
    """Extract phone numbers from text"""
    phone_regex = r"(\+?\d{1,3}[-.\s]?)?\(?\d{2,3}\)?[-.\s]?\d{2,4}[-.\s]?\d{2,4}"
    return list(set(re.findall(phone_regex, text)))

def extract_links(html: str, base_url: str) -> List[str]:
    """Extract all links from HTML content"""
    soup = BeautifulSoup(html, 'html.parser')
    links = set()
    
    for tag in soup.find_all(['a', 'link', 'script', 'img', 'iframe']):
        attr = 'href' if tag.name in ['a', 'link'] else 'src'
        if tag.has_attr(attr):
            url = urljoin(base_url, tag[attr])
            links.add(url)
    
    return list(links)

def is_interesting_file(url: str, interesting_exts: List[str]) -> bool:
    """Check if URL points to an interesting file"""
    return any(url.lower().endswith(ext) for ext in interesting_exts)