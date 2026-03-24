"""
VORTEX Security Intelligence - Parser de Logs
Convierte logs de seguridad en JSON estructurado.
Formato esperado:
[YYYY-MM-DD HH:MM:SS] [SEVERITY] Type: TYPE | IP: IP [BANEADO POR X] | URI: /ruta | Method: GET/POST | UA: user-agent
"""

import re
from datetime import datetime


# Expresión regular robusta para parsear logs de seguridad
LOG_PATTERN = re.compile(
    r'\[(?P<fecha>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\]\s*'
    r'\[(?P<severidad>[A-Z_]+)\]\s*'
    r'Type:\s*(?P<tipo>[^|]+?)\s*\|\s*'
    r'IP:\s*(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    r'(?:\s*\[BANEADO POR\s+(?P<baneado>[^\]]+)\])?\s*\|\s*'
    r'URI:\s*(?P<uri>[^|]+?)\s*\|\s*'
    r'Method:\s*(?P<metodo>[A-Z]+)\s*\|\s*'
    r'UA:\s*(?P<user_agent>.+?)$',
    re.MULTILINE
)

# Patrón alternativo más flexible
LOG_PATTERN_FLEXIBLE = re.compile(
    r'\[(?P<fecha>[^\]]+)\]\s*'
    r'\[(?P<severidad>[^\]]+)\]\s*'
    r'(?:Type:\s*(?P<tipo>[^|]+?)\s*\|)?\s*'
    r'(?:IP:\s*(?P<ip>[\d.]+)(?:\s*\[BANEADO POR\s+(?P<baneado>[^\]]*)\])?\s*\|)?\s*'
    r'(?:URI:\s*(?P<uri>[^|]+?)\s*\|)?\s*'
    r'(?:Method:\s*(?P<metodo>[A-Z]+)\s*\|)?\s*'
    r'(?:UA:\s*(?P<user_agent>.+?))?$',
    re.MULTILINE
)


def parsear_linea(linea):
    """
    Parsea una línea individual de log y retorna un diccionario estructurado.
    Intenta primero el patrón estricto, luego el flexible.
    """
    linea = linea.strip()
    if not linea:
        return None

    # Intento 1: patrón estricto
    match = LOG_PATTERN.match(linea)
    if not match:
        # Intento 2: patrón flexible
        match = LOG_PATTERN_FLEXIBLE.match(linea)

    if not match:
        return None

    datos = match.groupdict()

    # Limpiar y normalizar campos
    resultado = {
        'fecha': datos.get('fecha', '').strip(),
        'ip': datos.get('ip', '0.0.0.0').strip() if datos.get('ip') else '0.0.0.0',
        'severidad': datos.get('severidad', 'INFO').strip().upper(),
        'tipo': datos.get('tipo', 'DESCONOCIDO').strip() if datos.get('tipo') else 'DESCONOCIDO',
        'uri': datos.get('uri', '/').strip() if datos.get('uri') else '/',
        'metodo': datos.get('metodo', 'GET').strip() if datos.get('metodo') else 'GET',
        'user_agent': datos.get('user_agent', 'Desconocido').strip() if datos.get('user_agent') else 'Desconocido',
        'baneado': datos.get('baneado', '').strip() if datos.get('baneado') else ''
    }

    # Validar fecha
    try:
        datetime.strptime(resultado['fecha'], '%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError):
        resultado['fecha'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    return resultado


def parsear_logs(texto_logs):
    """
    Parsea múltiples líneas de logs y retorna una lista de diccionarios.
    Es tolerante a errores: las líneas que no se puedan parsear se ignoran.
    """
    resultados = []
    lineas_fallidas = 0

    for linea in texto_logs.split('\n'):
        linea = linea.strip()
        if not linea:
            continue

        resultado = parsear_linea(linea)
        if resultado:
            resultados.append(resultado)
        else:
            lineas_fallidas += 1

    return {
        'logs': resultados,
        'total_parseados': len(resultados),
        'total_fallidos': lineas_fallidas,
        'total_lineas': len(resultados) + lineas_fallidas
    }


def leer_archivo_log(ruta_archivo):
    """
    Lee un archivo de log y lo parsea.
    """
    try:
        with open(ruta_archivo, 'r', encoding='utf-8', errors='ignore') as f:
            contenido = f.read()
        return parsear_logs(contenido)
    except FileNotFoundError:
        return {'logs': [], 'total_parseados': 0, 'total_fallidos': 0, 'total_lineas': 0, 'error': f'Archivo no encontrado: {ruta_archivo}'}
    except Exception as e:
        return {'logs': [], 'total_parseados': 0, 'total_fallidos': 0, 'total_lineas': 0, 'error': str(e)}


def extraer_user_agent_info(ua_string):
    """
    Extrae información del sistema operativo y navegador del User-Agent.
    """
    ua = ua_string.lower()

    # Detectar OS
    os_name = 'Desconocido'
    if 'windows' in ua:
        os_name = 'Windows'
    elif 'mac' in ua or 'darwin' in ua:
        os_name = 'macOS'
    elif 'linux' in ua:
        os_name = 'Linux'
    elif 'android' in ua:
        os_name = 'Android'
    elif 'iphone' in ua or 'ipad' in ua or 'ios' in ua:
        os_name = 'iOS'

    # Detectar navegador
    browser = 'Desconocido'
    if 'sqlmap' in ua:
        browser = 'SQLMap (Herramienta)'
    elif 'nmap' in ua:
        browser = 'Nmap (Scanner)'
    elif 'nikto' in ua:
        browser = 'Nikto (Scanner)'
    elif 'curl' in ua:
        browser = 'cURL'
    elif 'python' in ua:
        browser = 'Python (Bot)'
    elif 'go-http' in ua:
        browser = 'Go HTTP (Bot)'
    elif 'wget' in ua:
        browser = 'Wget'
    elif 'chrome' in ua and 'edg' in ua:
        browser = 'Edge'
    elif 'chrome' in ua:
        browser = 'Chrome'
    elif 'firefox' in ua:
        browser = 'Firefox'
    elif 'safari' in ua:
        browser = 'Safari'
    elif 'opera' in ua or 'opr/' in ua:
        browser = 'Opera'

    return {'os': os_name, 'browser': browser}
