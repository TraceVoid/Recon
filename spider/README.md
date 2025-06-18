# 🕷️ Web Spider

**Web Spider** es una herramienta de reconocimiento web avanzada escrita en Python.

Permite realizar crawling, escaneo con Nmap y Nuclei, detección de tecnologías, pruebas básicas de vulnerabilidades (XSS, SQLi, redirecciones abiertas), extracción de correos y teléfonos, y generación de mapas visuales del sitio.

## 🚀 Uso básico

```bash
webspider https://example.com -d 2 -t 10 --no-nmap
```

## 📦 Características

- Multithreading para mayor velocidad
- Escaneo con Nmap y Nuclei (opcional)
- Crawling por profundidad controlada
- Detección de CMS y tecnologías
- Resultados exportados a JSON y Graphviz
