import socket
import ssl
import dns.resolver
from typing import Dict, List, Any
from datetime import datetime

def get_dns_info(domain: str) -> Dict[str, List[str]]:
    """Get DNS information for a domain"""
    dns_info = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            dns_info[record_type] = [str(r) for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            continue
    
    return dns_info

def get_ssl_cert(hostname: str) -> Dict[str, Any]:
    """Get SSL certificate information"""
    cert_info = {
        "issuer": {},
        "subject": {},
        "version": "Unknown",
        "serialNumber": "Unknown",
        "notBefore": "Unknown",
        "notAfter": "Unknown",
        "expired": False
    }
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                if cert:
                    cert_info.update({
                        "issuer": dict(x[0] for x in cert.get('issuer', [])),
                        "subject": dict(x[0] for x in cert.get('subject', [])),
                        "version": cert.get('version', 'Unknown'),
                        "serialNumber": cert.get('serialNumber', 'Unknown'),
                        "notBefore": cert.get('notBefore', 'Unknown'),
                        "notAfter": cert.get('notAfter', 'Unknown')
                    })
                    
                    if 'notAfter' in cert:
                        expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        cert_info["expired"] = expire_date < datetime.now()
    
    except (socket.gaierror, ssl.SSLError, ConnectionRefusedError) as e:
        print(f"SSL certificate error: {e}")
    
    return cert_info