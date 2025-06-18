import json
from pathlib import Path
from datetime import datetime
from graphviz import Digraph
from .cli import parse_args
from .config import setup_scan_dir
from .scanner import WebScanner

def main():
    args = parse_args()
    scan_dir = setup_scan_dir(args.output)
    
    scanner = WebScanner(
        start_url=args.url,
        max_depth=args.depth,
        threads=args.threads,
        no_nmap=args.no_nmap,
        no_nuclei=args.no_nuclei
    )
    
    print(f"Starting scan of {args.url}...")
    scan_data = scanner.run_full_scan()
    
    save_results(scan_data, scan_dir)
    generate_report(scan_data, scan_dir)
    
    print_summary(scan_data)

def save_results(data: dict, scan_dir: Path):
    """Save scan results to JSON file"""
    output_file = scan_dir / "scan_results.json"
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"Results saved to {output_file}")

def generate_report(data: dict, scan_dir: Path):
    """Generate visual report of the scan"""
    dot = Digraph(comment='Website Map')
    
    for page in data.get('pages', []):
        dot.node(page.url, page.url)
        # Here you would add edges based on links found
    
    map_file = scan_dir / "site_map.gv"
    dot.render(map_file, view=False)
    print(f"Site map generated at {map_file}")

def print_summary(data: dict):
    """Print summary of findings"""
    pages = data.get('pages', [])
    print("\nScan Summary:")
    print(f"- Pages scanned: {len(pages)}")
    print(f"- Vulnerabilities found: {sum(1 for p in pages if p.vulnerabilities.xss or p.vulnerabilities.sqli)}")
    print(f"- Interesting files: {sum(1 for p in pages if p.interesting_file)}")
    
    if data.get('ssl_info', {}).get('expired', False):
        print("⚠️ Expired SSL certificate detected!")
    
    if data.get('dns_info', {}).get('MX', []):
        print(f"- Mail servers: {', '.join(data['dns_info']['MX'])}")

if __name__ == "__main__":
    main()