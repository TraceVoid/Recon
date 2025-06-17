import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from graphviz import Digraph
import json
import time
import subprocess
import os
from datetime import datetime
import argparse
import concurrent.futures
import socket
import dns.resolver
import ssl
import re
from tqdm import tqdm

# CONFIGURACIÓN GENERAL
def parse_args():
    parser = argparse.ArgumentParser(description='Herramienta de reconocimiento web')
    parser.add_argument('url', help='URL para el recon')
    parser.add_argument('-d', '--depth', type=int, default=2, help='Profundidad máxima del spider')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Número de hilos para requests')
    parser.add_argument('--no-nmap', action='store_true', help='No ejecutar escaneo Nmap')
    parser.add_argument('--no-nuclei', action='store_true', help='No ejecutar Nuclei')
    return parser.parse_args()

args = parse_args()
start_url = args.url.rstrip('/')
visited = set()
max_depth = args.depth
output_json = []
dot = Digraph(comment='Mapa del Sitio')

# Crear carpeta de escaneo con timestamp
scan_folder = f"Escaneo_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
os.makedirs(scan_folder, exist_ok=True)

# Headers personalizados
custom_headers = {
    "User-Agent": "Mozilla/5.0 (SpiderBot)",
    "Accept": "text/html,application/xhtml+xml",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive"
}

# Extensiones sospechosas
interesting_extensions = [
    ".zip", ".sql", ".env", ".php", ".js", ".bak", ".log", ".txt", 
    ".conf", ".git", ".tar", ".gz", ".rar", ".7z", ".csv", ".xls", 
    ".xlsx", ".doc", ".docx", ".pdf", ".pem", ".key", ".ppk"
]

# Archivos y directorios comunes
common_files = [
    "robots.txt", "sitemap.xml", ".git/HEAD", ".env", 
    "admin", "wp-admin", "config.php", "backup.zip"
]

# Payloads para pruebas
xss_payloads = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "javascript:alert(1)"
]

sqli_payloads = [
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--"
]

# ---------- FUNCIONES AUXILIARES ----------
def is_valid_url(url):
    """Verifica si la URL pertenece al mismo dominio"""
    parsed_start = urlparse(start_url)
    parsed = urlparse(url)
    return (parsed.netloc == parsed_start.netloc or not parsed.netloc) and \
           parsed.scheme in ['http', 'https']

def is_interesting_file(url):
    """Verifica si la URL apunta a un archivo interesante"""
    return any(url.lower().endswith(ext) for ext in interesting_extensions)

def detect_tech(url, response):
    """Detecta tecnologías utilizadas en el sitio"""
    tech = {
        "server": response.headers.get("Server", ""),
        "x_powered_by": response.headers.get("X-Powered-By", ""),
        "framework": "Desconocido",
        "cms": "Desconocido",
        "languages": []
    }
    
    # Detección de CMS
    if "wp-content" in response.text:
        tech["cms"] = "WordPress"
    elif "/joomla/" in response.text.lower():
        tech["cms"] = "Joomla"
    elif "/drupal/" in response.text.lower():
        tech["cms"] = "Drupal"
    
    # Detección de frameworks
    if "/static/" in response.text or "react" in response.text.lower():
        tech["framework"] = "React o SPA"
    elif "laravel" in response.text.lower():
        tech["framework"] = "Laravel"
    
    # Detección de lenguajes
    if ".php" in response.text.lower():
        tech["languages"].append("PHP")
    if ".aspx" in response.text.lower():
        tech["languages"].append("ASP.NET")
    if "node.js" in response.text.lower():
        tech["languages"].append("Node.js")
    
    # Cookies reveladoras
    cookies = response.headers.get("Set-Cookie", "")
    if "PHPSESSID" in cookies:
        tech["languages"].append("PHP")
    if "JSESSIONID" in cookies:
        tech["languages"].append("Java")
    
    return tech

def scan_with_nuclei(url):
    """Ejecuta Nuclei para detectar vulnerabilidades conocidas"""
    if args.no_nuclei:
        return []
    
    try:
        result = subprocess.run([
            "nuclei", "-u", url, "-silent", "-json", "-severity", "low,medium,high,critical"
        ], capture_output=True, text=True, timeout=300)
        if result.stdout:
            findings = [json.loads(line) for line in result.stdout.strip().split('\n') if line]
            return findings
    except Exception as e:
        print(f"  ❌ Error ejecutando nuclei en {url}: {e}")
    return []

def test_vulnerabilities(url):
    """Prueba vulnerabilidades XSS y SQLi básicas"""
    results = {"xss": False, "sqli": False, "open_redirect": False}
    
    # Test XSS
    for payload in xss_payloads:
        try:
            r_xss = requests.get(url, params={"q": payload}, headers=custom_headers, timeout=5)
            if payload in r_xss.text:
                results["xss"] = True
                break
        except:
            pass
    
    # Test SQLi
    for payload in sqli_payloads:
        try:
            r_sqli = requests.get(url, params={"id": payload}, headers=custom_headers, timeout=5)
            if "error" in r_sqli.text.lower() or "syntax" in r_sqli.text.lower() or "mysql" in r_sqli.text.lower():
                results["sqli"] = True
                break
        except:
            pass
    
    # Test Open Redirect
    try:
        test_url = urljoin(url, "?redirect=http://evil.com")
        r_redirect = requests.get(test_url, headers=custom_headers, allow_redirects=False, timeout=5)
        if r_redirect.status_code in [301, 302] and "evil.com" in r_redirect.headers.get("Location", ""):
            results["open_redirect"] = True
    except:
        pass
    
    return results

def run_nmap_scan(host):
    """Ejecuta un escaneo básico de Nmap"""
    if args.no_nmap:
        return ""
    
    try:
        print(f"  🛰️ Ejecutando Nmap en {host}...")
        output_file = os.path.join(scan_folder, f"nmap_{host.replace('.', '_')}.txt")
        
        # Escaneo más completo pero con tiempos ajustados
        subprocess.run([
            "nmap", "-sV", "-T4", "--min-rate", "1000", 
            "--script", "vulners,banner,http-title", 
            "-Pn", host, "-oN", output_file
        ], timeout=1800)
        
        return output_file
    except Exception as e:
        print(f"  ❌ Error ejecutando Nmap: {e}")
        return ""

def check_common_files(url):
    """Verifica la existencia de archivos y directorios comunes"""
    found = []
    for file in common_files:
        try:
            test_url = urljoin(url, file)
            response = requests.head(test_url, headers=custom_headers, timeout=5)
            if response.status_code == 200:
                found.append(test_url)
                print(f"  🔍 Archivo común encontrado: {test_url}")
        except:
            pass
    return found

def get_dns_info(domain):
    """Obtiene información DNS del dominio"""
    dns_info = {}
    try:
        # Resolución de registros comunes
        for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                dns_info[record_type] = [str(r) for r in answers]
            except:
                pass
    except Exception as e:
        print(f"  ❌ Error en resolución DNS: {e}")
    return dns_info

def get_ssl_cert(hostname):
    """Obtiene información del certificado SSL"""
    cert_info = {}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                # Información básica del certificado
                cert_info = {
                    "issuer": dict(x[0] for x in cert['issuer']),
                    "subject": dict(x[0] for x in cert['subject']),
                    "version": cert.get('version', 'Desconocido'),
                    "serialNumber": cert.get('serialNumber', 'Desconocido'),
                    "notBefore": cert.get('notBefore', 'Desconocido'),
                    "notAfter": cert.get('notAfter', 'Desconocido'),
                    "expired": False
                }
                
                # Verificar si el certificado ha expirado
                if 'notAfter' in cert:
                    expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    cert_info["expired"] = expire_date < datetime.now()
    except Exception as e:
        print(f"  ❌ Error obteniendo certificado SSL: {e}")
    return cert_info

def extract_emails(text):
    """Extrae emails del texto de la página"""
    email_regex = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    return re.findall(email_regex, text)

def extract_phone_numbers(text):
    """Extrae números de teléfono del texto de la página"""
    phone_regex = r"(\+?\d{1,3}[-.\s]?)?\(?\d{2,3}\)?[-.\s]?\d{2,4}[-.\s]?\d{2,4}"
    return re.findall(phone_regex, text)

def extract_links(text, base_url):
    """Extrae enlaces del texto HTML"""
    soup = BeautifulSoup(text, 'html.parser')
    links = []
    
    for tag in soup.find_all(['a', 'link', 'script', 'img', 'iframe']):
        attr = 'href' if tag.name in ['a', 'link'] else 'src'
        if tag.has_attr(attr):
            url = urljoin(base_url, tag[attr])
            if is_valid_url(url):
                links.append(url)
    
    return links

def process_page(url, depth, parent=None):
    """Procesa una página individual"""
    if depth > max_depth or url in visited:
        return None
    
    try:
        print(f"[{depth}] Visitando: {url}")
        response = requests.get(url, headers=custom_headers, timeout=10)
        visited.add(url)
        
        # Añadir al gráfico
        dot.node(url, url)
        if parent:
            dot.edge(parent, url)
        
        # Extraer información
        tech_info = detect_tech(url, response)
        vuln_results = test_vulnerabilities(url)
        common_files_found = check_common_files(url)
        emails = extract_emails(response.text)
        phones = extract_phone_numbers(response.text)
        nuclei_results = scan_with_nuclei(url)
        
        result = {
            "url": url,
            "depth": depth,
            "status_code": response.status_code,
            "content_type": response.headers.get("Content-Type", ""),
            "content_length": len(response.content),
            "headers": dict(response.headers),
            "interesting_file": is_interesting_file(url),
            "tech_detected": tech_info,
            "nuclei_findings": nuclei_results,
            "xss_detected": vuln_results["xss"],
            "sqli_detected": vuln_results["sqli"],
            "open_redirect": vuln_results["open_redirect"],
            "common_files_found": common_files_found,
            "emails_found": emails,
            "phone_numbers": phones,
            "timestamp": datetime.now().isoformat()
        }
        
        # Mostrar hallazgos importantes
        if result["interesting_file"]:
            print(f"  ⚠️ Archivo interesante detectado: {url}")
        if result["nuclei_findings"]:
            print(f"  💥 {len(result['nuclei_findings'])} vulnerabilidades detectadas por Nuclei!")
        if result["xss_detected"]:
            print(f"  🛑 Posible XSS detectado en {url}")
        if result["sqli_detected"]:
            print(f"  🛑 Posible SQLi detectado en {url}")
        if result["open_redirect"]:
            print(f"  🚩 Posible Open Redirect en {url}")
        if common_files_found:
            print(f"  🔍 {len(common_files_found)} archivos comunes encontrados")
        
        return result
        
    except Exception as e:
        print(f"  ❌ Error en {url}: {e}")
        return None

# ---------- SPIDER CON HILOS ----------
def spider(start_url):
    """Spider que utiliza hilos para procesar páginas"""
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(process_page, start_url, 0): start_url}
        visited.add(start_url)
        
        while futures:
            done, _ = concurrent.futures.wait(futures, return_when=concurrent.futures.FIRST_COMPLETED)
            
            for future in done:
                url = futures.pop(future)
                result = future.result()
                
                if result:
                    output_json.append(result)
                    
                    # Si es HTML, extraer enlaces para seguir explorando
                    if "text/html" in result["content_type"] and result["depth"] < max_depth:
                        try:
                            response = requests.get(url, headers=custom_headers, timeout=5)
                            links = extract_links(response.text, url)
                            
                            for link in links:
                                if link not in visited:
                                    visited.add(link)
                                    futures[executor.submit(process_page, link, result["depth"] + 1, url)] = link
                        except:
                            pass

# ---------- INICIO ----------
def main():
    print(f"\n🔍 Iniciando reconocimiento en {start_url}...\n")
    
    # Obtener información del dominio
    parsed_url = urlparse(start_url)
    domain = parsed_url.netloc.split(':')[0]
    
    print("🌐 Obteniendo información DNS...")
    dns_info = get_dns_info(domain)
    
    print("🔐 Analizando certificado SSL...")
    ssl_info = get_ssl_cert(domain)
    
    # Ejecutar Nmap
    nmap_file = run_nmap_scan(domain)
    
    # Ejecutar spider
    print("\n🕷️ Iniciando spider...")
    spider(start_url)
    
    # Guardar resultados
    print("\n💾 Guardando resultados...")
    with open(os.path.join(scan_folder, "hallazgos.json"), "w") as f:
        json.dump({
            "target": start_url,
            "date": datetime.now().isoformat(),
            "dns_info": dns_info,
            "ssl_info": ssl_info,
            "scan_results": output_json,
            "nmap_scan": nmap_file
        }, f, indent=2, ensure_ascii=False)
    
    # Generar mapa del sitio
    map_file = os.path.join(scan_folder, "site_map.gv")
    dot.render(map_file, view=False)
    
    print(f"\n✅ Reconocimiento completo. Resultados en '{scan_folder}'")
    
    # Resumen de hallazgos
    total_vulns = sum(len(r.get("nuclei_findings", [])) for r in output_json)
    print(f"\n Resumen:")
    print(f"- Páginas analizadas: {len(output_json)}")
    print(f"- Vulnerabilidades encontradas: {total_vulns}")
    print(f"- Archivos interesantes: {sum(1 for r in output_json if r['interesting_file'])}")
    print(f"- Posibles XSS: {sum(1 for r in output_json if r['xss_detected'])}")
    print(f"- Posibles SQLi: {sum(1 for r in output_json if r['sqli_detected'])}")

if __name__ == "__main__":
    main()