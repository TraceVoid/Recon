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

## 🔧 Modo de Uso Básico

```bash
python spider.py https://ejemplo.com
```

---

## ⚙️ Opciones Avanzadas

```bash
python spider.py https://ejemplo.com [OPCIONES]
```

| Argumento         | Descripción                                             | Ejemplo               |
| ----------------- | ------------------------------------------------------- | --------------------- |
| URL (obligatorio) | URL objetivo para el reconocimiento                     | `https://ejemplo.com` |
| `-d`, `--depth`   | Profundidad máxima del spider (default: 2)              | `-d 3`                |
| `-t`, `--threads` | Número de hilos para requests concurrentes (default: 5) | `-t 10`               |
| `--no-nmap`       | Desactiva escaneo Nmap                                  | `--no-nmap`           |
| `--no-nuclei`     | Desactiva escaneo con Nuclei                            | `--no-nuclei`         |

---

## 📌 Ejemplos Prácticos

### 1. Escaneo estándar:

```bash
python spider.py https://ejemplo.com -d 2 -t 8
```

### 2. Escaneo rápido (sin Nmap y Nuclei):

```bash
python spider.py https://ejemplo.com --no-nmap --no-nuclei
```

### 3. Escaneo profundo:

```bash
python spider.py https://ejemplo.com -d 3 -t 15
```

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

## 📁 Estructura de Salida

Cada ejecución genera una carpeta automática:

```
📂 Escaneo_YYYYMMDD_HHMMSS/
├── hallazgos.json         → Resultados estructurados del reconocimiento
├── site_map.gv            → Mapa del sitio en Graphviz
├── site_map.gv.pdf        → Versión visual (si Graphviz está instalado)
├── nmap_target.txt        → Resultado del escaneo Nmap (opcional)
```

---

## 🧠 Tips Avanzados

### ▶️ Requisitos para el mapa visual:

```bash
# Linux
sudo apt install graphviz

# macOS
brew install graphviz

# Windows (Chocolatey)
choco install graphviz
```

Convertir a imagen:

```bash
dot -Tpng site_map.gv -o mapa.png
```

### ⚠️ Nmap requiere privilegios:

```bash
sudo python spider.py https://ejemplo.com
```

### 🔎 Uso combinado con otras herramientas:

```bash
nuclei -u https://ejemplo.com -t ~/nuclei-templates/
```

---

## 🚨 Advertencias Importantes

* ⚠️ **Solo usar en sistemas con autorización explícita.**
* 🐢 Hilos altos (`-t`) pueden saturar servidores mal configurados.
* 🔍 Pruebas profundas (`-d > 2`) pueden consumir mucho tiempo.
* 📈 Si el sitio es muy grande, considera un escaneo por secciones.

---

## 📦 Tecnologías utilizadas

* **Python 3.8+**
* `requests`, `bs4`, `graphviz`, `tqdm`, `argparse`, `concurrent.futures`
* Herramientas externas: **Nmap**, **Nuclei**, **Graphviz**

---

## ✨ Pendientes / Ideas futuras

* Interfaz web para visualizar hallazgos
* Exportación a PDF/HTML de forma automática
* Dashboards con JS o frameworks como Streamlit
* Integración con Shodan / Censys
* Módulo adicional en Rust o Go para detección ultra rápida de servicios

---

## 🤝 Créditos

Desarrollado por \[Tu Nombre] como parte de una suite de herramientas para pruebas de penetración y evaluación de seguridad web. Inspirado por la necesidad de automatizar tareas repetitivas sin depender de soluciones comerciales.
