import argparse
from datetime import datetime

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Herramienta de reconocimiento web')
    parser.add_argument('url', help='URL para el recon')
    parser.add_argument('-d', '--depth', type=int, default=2, 
                       help='Profundidad máxima del spider (default: 2)')
    parser.add_argument('-t', '--threads', type=int, default=5,
                       help='Número de hilos para requests (default: 5)')
    parser.add_argument('--no-nmap', action='store_true', 
                       help='No ejecutar escaneo Nmap')
    parser.add_argument('--no-nuclei', action='store_true',
                       help='No ejecutar Nuclei')
    parser.add_argument('-o', '--output', 
                       default=f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                       help='Directorio de salida para los resultados')
    return parser.parse_args()