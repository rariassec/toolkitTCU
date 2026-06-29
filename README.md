# toolkitTCU

Suite de seguridad para el TCU. Integra tres módulos de análisis en una sola
herramienta. La forma recomendada de uso es la interfaz web, que reúne los tres
módulos, el historial de reportes y su descarga en un solo lugar. También se
incluye una interfaz de consola como alternativa.

Los módulos son:

- Análisis Web: revisa la seguridad de un sitio (headers HTTP, SSL/TLS,
  archivos expuestos, metadatos de documentos y más).
- Análisis de Red: escaneo de puertos, detección de servicios vulnerables,
  conexiones sospechosas, análisis DNS y cálculo de riesgo.
- Integridad de Archivos (FIM): vigila cambios en archivos y carpetas mediante
  huellas criptográficas, con monitoreo continuo y alertas.

Todos los módulos generan reportes en JSON y PDF, y pueden consolidarse en un
reporte unificado.

## Requisitos

- Python 3.10 o superior.
- nmap instalado en el sistema (lo usa el módulo de red):
  - Debian/Ubuntu: `sudo apt install nmap`
  - Fedora: `sudo dnf install nmap`
  - Arch: `sudo pacman -S nmap`
  - macOS: `brew install nmap`
- Privilegios de administrador (sudo) para algunos escaneos de red y la captura
  de tráfico.

## Instalación

Desde la carpeta del proyecto:

```
python install.py
```

El instalador instala las dependencias de Python listadas en
`requirements.txt` y verifica que nmap esté disponible. Si falta nmap, muestra
el comando de instalación correspondiente al sistema operativo.

## Uso

### Interfaz web (recomendada)

Es la forma principal de ejecutar el toolkit. Desde la carpeta del proyecto:

```
python run_web.py
```

Abre la aplicación en `http://127.0.0.1:5000`. En el navegador se accede a los
tres módulos, al historial de reportes y a su descarga, sin necesidad de usar
la consola.

Para escaneos de red que requieren privilegios, inicie la interfaz con sudo:

```
sudo $(which python) run_web.py
```

Variables de entorno opcionales:

- `TCU_WEB_HOST`: dirección de escucha (por defecto `127.0.0.1`).
- `TCU_WEB_PORT`: puerto (por defecto `5000`).
- `TCU_WEB_DEBUG`: `1` para activar el modo depuración.

### Interfaz de consola (alternativa)

Disponible para entornos sin navegador o uso por terminal. Ofrece las mismas
capacidades de análisis que la web.

```
python run.py
```

Para escaneos de red que requieren privilegios, ejecútelo con sudo:

```
sudo $(which python) run.py
```

Presenta un menú con las opciones:

1. Análisis Web
2. Análisis de Red
3. Integridad de Archivos
4. Reporte unificado (consolida lo analizado en la sesión actual)
0. Salir

El reporte unificado no ejecuta análisis nuevos: consolida los resultados ya
obtenidos en la sesión. Ejecute primero las opciones 1, 2 o 3.

## Módulos

### Análisis Web

Evalúa un sitio mediante cinco escáneres, todos opcionales:

- Verificador de Headers HTTP.
- Auditor SSL/TLS.
- Detector de Archivos Expuestos.
- Analizador de Metadatos en Documentos.
- Funcionalidades Adicionales (cookies, robots.txt, tecnologías).

Se indica una URL o dominio. Cada escáner entrega hallazgos con severidad y un
puntaje; el módulo calcula un puntaje global de 0 a 100.

### Análisis de Red

Sobre una IP, dominio o rango de red:

- Escaneo de puertos TCP.
- Escaneo de puertos UDP.
- Escaneo personalizado (parámetros de nmap definidos por el usuario).
- Detección de servicios vulnerables (busca CVEs; requiere un escaneo previo).
- Detección de conexiones sospechosas (tráfico saliente anómalo).
- Análisis DNS.
- Cálculo de riesgo (puntaje consolidado de 0 a 10).
- Reportería del módulo (JSON y PDF).

Recomendación: ejecute primero un escaneo de puertos para que la detección de
vulnerabilidades y el cálculo de riesgo tengan datos.

API Keys: la detección de vulnerabilidades puede usar claves de VirusTotal o
NVD. Se configuran desde el propio módulo (menú de consola o sección
correspondiente en la web).

### Integridad de Archivos (FIM)

Vigila cambios en archivos y carpetas:

- Almacenar hash: guarda la huella de un archivo o carpeta. Algoritmos
  disponibles: SHA-256 (recomendado), SHA-512, BLAKE2b y SHA3-256.
- Detección manual: compara el estado actual contra las huellas guardadas.
- Monitoreo continuo: detecta cambios en tiempo real sobre las rutas
  configuradas (iniciar/detener desde la web).
- Baseline: revisa y gestiona los cambios detectados.
- Estadísticas y gráficos del monitoreo.
- Reportes: exporta el historial en JSON, TXT o PDF (incluye resumen ejecutivo
  con gráficos y recomendaciones).
- Reconfiguración de las rutas vigiladas (rutas, recursividad, algoritmo e
  intervalo de escaneo).
- Alertas por correo: configura el envío de alertas por email.

## Reportes

Los reportes de cada módulo y el reporte unificado se guardan en formato JSON y
PDF dentro de la carpeta `reportes/`. Desde la interfaz web se pueden listar y
descargar.

El reporte unificado resume, por módulo, el estado, el conteo de hallazgos por
severidad (CRITICAL, HIGH, MEDIUM, LOW, INFO), un puntaje global y el detalle
de cada hallazgo con su recomendación.

## Pruebas

```
pytest
```

## Licencia

Ver el archivo `LICENSE`.
