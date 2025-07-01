import concurrent.futures
import requests
from typing import List, Optional, Dict, Set, Any
from pathlib import Path
from urllib.parse import urlparse

from .models.scan_result import ScanResult, TechInfo, VulnerabilityResults
from .utils import (
    network_utils, 
    vuln_utils, 
    file_utils,
    tech_detector,
    dns_utils
)
from .config import (
    HEADERS,
    INTERESTING_EXTENSIONS,
    COMMON_FILES,
    REQUEST_TIMEOUT
)

class WebScanner:
    def __init__(self, start_url: str, max_depth: int = 2, threads: int = 5, 
                 no_nmap: bool = False, no_nuclei: bool = False):
        self.start_url = start_url.rstrip('/')
        self.max_depth = max_depth
        self.threads = threads
        self.no_nmap = no_nmap
        self.no_nuclei = no_nuclei
        self.visited: Set[str] = set()
        self.results: List[ScanResult] = []
        self.domain = urlparse(start_url).netloc.split(':')[0]
    
    def run_full_scan(self) -> Dict[str, Any]:
        """Run complete scan including DNS, SSL, Nmap and web spider"""
        scan_data = {
            "target": self.start_url,
            "dns_info": dns_utils.get_dns_info(self.domain),
            "ssl_info": dns_utils.get_ssl_cert(self.domain),
            "nmap_scan": self._run_nmap_scan(),
            "pages": self.run_spider()
        }
        return scan_data
    
    def run_spider(self) -> List[ScanResult]:
        """Run only the web spider component"""
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._scan_page, self.start_url, 0): self.start_url}
            self.visited.add(self.start_url)
            
            while futures:
                done, _ = concurrent.futures.wait(
                    futures, 
                    return_when=concurrent.futures.FIRST_COMPLETED
                )
                
                for future in done:
                    url = futures.pop(future)
                    result = future.result()
                    
                    if result:
                        self.results.append(result)
                        self._process_links(result, executor, futures)
        
        return self.results
    
    def _scan_page(self, url: str, depth: int) -> Optional[ScanResult]:
        """Scan an individual page"""
        if depth > self.max_depth or url in self.visited:
            return None
            
        try:
            response = requests.get(
                url, 
                headers=HEADERS, 
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True
            )
            self.visited.add(url)
            
            tech_info = tech_detector.detect_tech_from_content(
                response.text,
                dict(response.headers)
            )
            
            vulns = vuln_utils.test_vulnerabilities(url)
            common_files = self._check_common_files(url)
            
            return ScanResult(
                url=url,
                depth=depth,
                status_code=response.status_code,
                content_type=response.headers.get("Content-Type", ""),
                content_length=len(response.content),
                headers=dict(response.headers),
                tech_info=tech_info,
                vulnerabilities=VulnerabilityResults(**vulns),
                common_files=common_files,
                emails=file_utils.extract_emails(response.text),
                phones=file_utils.extract_phones(response.text),
                interesting_file=file_utils.is_interesting_file(url, INTERESTING_EXTENSIONS)
            )
            
        except requests.RequestException as e:
            print(f"Error scanning {url}: {e}")
            return None
    
    def _process_links(self, result: ScanResult, executor, futures):
        """Process links from a scan result"""
        if (result.depth < self.max_depth and 
            "text/html" in result.content_type):
            try:
                links = file_utils.extract_links(result.content, result.url)
                for link in links:
                    if link not in self.visited:
                        self.visited.add(link)
                        futures[executor.submit(
                            self._scan_page, 
                            link, 
                            result.depth + 1
                        )] = link
            except Exception as e:
                print(f"Error processing links: {e}")
    
    def _check_common_files(self, base_url: str) -> List[str]:
        """Check for common interesting files"""
        found = []
        for file in COMMON_FILES:
            test_url = network_utils.join_urls(base_url, file)
            try:
                response = requests.head(
                    test_url, 
                    headers=HEADERS, 
                    timeout=5
                )
                if response.status_code == 200:
                    found.append(test_url)
            except requests.RequestException:
                continue
        return found
    
    def _run_nmap_scan(self) -> Optional[str]:
        """Run Nmap scan if enabled"""
        if self.no_nmap:
            return None
            
        try:
            import subprocess
            output_file = f"nmap_{self.domain.replace('.', '_')}.txt"
            subprocess.run([
                "nmap", "-sV", "-T4", self.domain,
                "-oN", output_file
            ], timeout=600)
            return output_file
        except Exception as e:
            print(f"Nmap scan failed: {e}")
            return None
