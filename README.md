```
                                   _
       /      \         __      _\( )/_
    \  \  ,,  /  /   | /  \ |    /(O)\ 
     '-.`\()/`.-'   \_\\  //_/    _.._   _\(o)/_  //  \\
    .--_'(  )'_--.   .'/()\'.   .'    '.  /(_)\  _\\()//_
   / /` /`""`\ `\ \   \\  //   /   __   \       / //  \\ \
    |  |  ><  |  |          ,  |   ><   |  ,     | \__/ |
    \  \      /  /         . \  \      /  / .              _
   _    '.__.'    _\(O)/_   \_'--`(  )'--'_/     __     _\(_)/_
_\( )/_            /(_)\      .--'/()\'--.    | /  \ |   /(O)\
 /(O)\  //  \\         _     /  /` '' `\  \  \_\\  //_/
       _\\()//_     _\(_)/_    |        |      //()\\ 
      / //  \\ \     /(o)\      \      /       \\  //
       | \__/ |
```
# 🕷️ RECON SCRIPT - Crawler y Análisis de Vulnerabilidades Web

Recon Script es una herramienta avanzada de reconocimiento web desarrollada en Python que combina funciones de crawling profundo, fingerprinting, pruebas de vulnerabilidades y generación de reportes detallados. Pensada para profesionales en seguridad ofensiva, permite automatizar gran parte del reconocimiento pasivo y activo con un solo comando.

---

## 📦 Requisitos Previos

```bash
# Linux (Debian/Ubuntu)
sudo apt update && sudo apt install -y graphviz python3-pip

# macOS
brew install graphviz

# Windows
choco install graphviz
```

---

## ⚙️ Instalación

```bash
git clone https://github.com/TraceVoid/Recon
cd Recon
pip install -r requirements.txt

```
# Herramientas externas (opcional)
```
sudo apt install -y nmap
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```
## 🧼 Instalación Limpia y Comprobación

```bash
cd Recon/spider
pip uninstall web-spider -y
pip install .

# Verificar comando
webspider --help

# Ejecución básica de prueba
webspider http://testphp.vulnweb.com -d 1 --no-nmap
```
---

## 🚀 Ejecución Básica

```bash
webspider https://ejemplo.com
```

Opciones comunes:

```bash
python spider.py https://ejemplo.com -d 2 -t 8
python spider.py https://ejemplo.com --no-nmap --no-nuclei
python spider.py https://ejemplo.com -d 3 -t 12 --output escaneo_completo
```

---

## 🛠️ Argumentos Avanzados

| Argumento         | Descripción                                              | Ejemplo                |
|-------------------|----------------------------------------------------------|------------------------|
| `url`             | URL objetivo del análisis                                | `https://ejemplo.com`  |
| `-d`, `--depth`   | Profundidad de crawling                                  | `-d 3`                 |
| `-t`, `--threads` | Número de hilos concurrentes                             | `-t 10`                |
| `--no-nmap`       | Desactiva el escaneo con Nmap                            | `--no-nmap`            |
| `--no-nuclei`     | Desactiva el escaneo con Nuclei                          | `--no-nuclei`          |
| `-o, --output`    | Directorio de salida para los resultados                 | `-o /ruta/archivo`     |
---

## 🔁 Flujo de Ejecución

1. **Reconocimiento inicial:**

   * Resolución DNS completa (A, AAAA, MX, NS, TXT, CNAME)
   * Análisis del certificado SSL (validez, emisor, expiración)
   * Escaneo con Nmap (opcional)

2. **Spider web multihilo:**

   * Rastreo recursivo con control de profundidad
   * Extracción de enlaces internos y externos
   * Detección de tecnologías: CMS, frameworks, servidores, lenguajes
   * Búsqueda de archivos sensibles (por extensión y rutas comunes)

3. **Pruebas de vulnerabilidades:**

   * XSS y SQLi básico (por inyección en parámetros)
   * Open Redirect (por manipulación de redirecciones)
   * Escaneo con Nuclei para CVEs y malas configuraciones

4. **Extracción de información pasiva:**

   * Emails expuestos en páginas
   * Números telefónicos en texto
   * Metadatos de cabeceras HTTP

5. **Generación de reportes:**

   * Resultados JSON (`hallazgos.json`)
   * Mapa visual del sitio en `.gv` y `.pdf` (usando Graphviz)
   * Archivo Nmap con detalles de puertos y servicios
   
---

## 📁 Salida del Escaneo

```
📂 Escaneo_YYYYMMDD_HHMMSS/
├── hallazgos.json         → Resultados estructurados
├── site_map.gv/pdf        → Mapa visual del sitio
├── nmap_target.txt        → Salida del escaneo Nmap (opcional)
```

Para generar un PNG:

```bash
dot -Tpng site_map.gv -o mapa_sitio.png
```

---

## 🧪 Análisis Rápido con `jq`

```bash
# Vulnerabilidades detectadas
jq '.scan_results[] | select(.nuclei_findings != [])' hallazgos.json

# URLs encontradas
jq '.scan_results[].url' hallazgos.json

# Archivos interesantes
jq '.scan_results[] | select(.interesting_file == true)' hallazgos.json
```

---

## 🔧 Problemas Comunes

**Falta módulo o dependencia**:
```bash
pip install -r requirements.txt
```

**Mapa no generado**:
```bash
dot -V  # verificar instalación de graphviz
```

**Escaneo lento**:
```bash
webspider https://ejemplo.com -d 1 -t 3
```

---

## 🧩 Ideas Futuras

- Interfaz visual con Streamlit
- Exportación a HTML interactivo
- Módulo rápido con Rust/Go
- Integración con APIs externas como Shodan

---
