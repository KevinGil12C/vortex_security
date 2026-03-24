"""
VORTEX Security Intelligence - Detector de Ataques
Clasifica y puntúa amenazas en logs de seguridad.
"""

import re
from collections import Counter, defaultdict


# ═══════════════════════════════════════════════════════════════
# PATRONES DE DETECCIÓN DE ATAQUES
# ═══════════════════════════════════════════════════════════════

PATRONES_SQLI = [
    r"(?:union\s+select|union\s+all\s+select)",
    r"(?:select\s+.*\s+from\s+)",
    r"(?:insert\s+into|update\s+.*\s+set|delete\s+from)",
    r"(?:drop\s+table|drop\s+database|truncate\s+table)",
    r"(?:;\s*(?:select|insert|update|delete|drop|alter|create))",
    r"(?:'\s*(?:or|and)\s+['\d])",
    r"(?:1\s*=\s*1|1\s*=\s*'1')",
    r"(?:sleep\s*\(|benchmark\s*\(|waitfor\s+delay)",
    r"(?:concat\s*\(|char\s*\(|0x[0-9a-f]+)",
    r"(?:information_schema|pg_catalog|sysobjects)",
    r"(?:load_file|into\s+(?:out|dump)file)",
    r"(?:having\s+\d|group\s+by\s+.*\d)",
    r"(?:%27|%22|%3B|%2D%2D)",
]

PATRONES_XSS = [
    r"(?:<script[^>]*>)",
    r"(?:javascript\s*:)",
    r"(?:on(?:error|load|click|mouseover|focus|blur|submit)\s*=)",
    r"(?:alert\s*\(|confirm\s*\(|prompt\s*\()",
    r"(?:<img[^>]+onerror)",
    r"(?:<(?:iframe|object|embed|applet|form|body))",
    r"(?:document\.(?:cookie|location|write))",
    r"(?:eval\s*\(|settimeout\s*\(|setinterval\s*\()",
    r"(?:%3Cscript|%3Csvg|%3Cimg)",
    r"(?:String\.fromCharCode)",
]

PATRONES_TRAVERSAL = [
    r"(?:\.\./|\.\.\%2[fF])",
    r"(?:/etc/(?:passwd|shadow|hosts|crontab))",
    r"(?:/proc/(?:self|version|cpuinfo))",
    r"(?:(?:c|d):\\\\(?:windows|boot\.ini))",
    r"(?:\.\.[\\/]{2,})",
    r"(?:%2e%2e[/\\]|%252e%252e)",
    r"(?:/var/log/|/tmp/|/root/)",
]

PATRONES_RECONOCIMIENTO = [
    r"(?:\.env|\.git|\.svn|\.htaccess|\.htpasswd)",
    r"(?:wp-admin|wp-login|wp-content|wp-includes)",
    r"(?:phpmyadmin|adminer|phpinfo)",
    r"(?:admin|administrator|login|panel|dashboard|manager)",
    r"(?:config\.|configuration\.|settings\.)",
    r"(?:backup|database|\.sql|\.db|\.bak|\.old)",
    r"(?:robots\.txt|sitemap\.xml|crossdomain\.xml)",
    r"(?:\.well-known|server-status|server-info)",
    r"(?:xmlrpc\.php|api/|graphql)",
    r"(?:\.zip|\.tar|\.gz|\.rar|\.7z)",
]

BOTS_CONOCIDOS = [
    'sqlmap', 'nmap', 'nikto', 'curl', 'wget', 'python-requests',
    'go-http-client', 'masscan', 'zmap', 'dirbuster', 'gobuster',
    'wfuzz', 'hydra', 'medusa', 'burpsuite', 'zaproxy', 'acunetix',
    'nessus', 'openvas', 'scrapy', 'httpclient', 'java/', 'libwww',
    'lwp-trivial', 'apache-httpclient', 'okhttp', 'python-urllib',
    'nuclei', 'httpx', 'subfinder', 'amass', 'whatweb', 'wapiti',
]

HONEYPOT_URIS = [
    '/trap', '/.env', '/.git/config', '/debug', '/test',
    '/backup', '/old', '/admin/config', '/phpinfo.php',
    '/wp-login.php', '/xmlrpc.php', '/actuator', '/api/debug',
    '/console', '/shell', '/cmd', '/exec', '/eval',
    '/.aws/credentials', '/.docker', '/server-status',
]


def _compilar_patrones(patrones):
    """Compila una lista de patrones regex."""
    return [re.compile(p, re.IGNORECASE) for p in patrones]


# Compilar patrones una sola vez
_SQLI_COMPILADOS = _compilar_patrones(PATRONES_SQLI)
_XSS_COMPILADOS = _compilar_patrones(PATRONES_XSS)
_TRAVERSAL_COMPILADOS = _compilar_patrones(PATRONES_TRAVERSAL)
_RECON_COMPILADOS = _compilar_patrones(PATRONES_RECONOCIMIENTO)


def detectar_tipo_ataque(log_entry):
    """
    Analiza un log parseado y detecta el tipo de ataque.
    Retorna lista de ataques detectados con score individual.
    """
    ataques = []
    uri = log_entry.get('uri', '')
    ua = log_entry.get('user_agent', '').lower()
    metodo = log_entry.get('metodo', '')
    tipo_orig = log_entry.get('tipo', '').lower()

    # ── SQL Injection ──
    for patron in _SQLI_COMPILADOS:
        if patron.search(uri):
            ataques.append({'tipo': 'SQL Injection', 'score': 85, 'evidencia': uri})
            break

    # ── XSS ──
    for patron in _XSS_COMPILADOS:
        if patron.search(uri):
            ataques.append({'tipo': 'XSS', 'score': 75, 'evidencia': uri})
            break

    # ── Directory Traversal ──
    for patron in _TRAVERSAL_COMPILADOS:
        if patron.search(uri):
            ataques.append({'tipo': 'Directory Traversal', 'score': 70, 'evidencia': uri})
            break

    # ── Reconocimiento ──
    for patron in _RECON_COMPILADOS:
        if patron.search(uri):
            ataques.append({'tipo': 'Reconocimiento', 'score': 50, 'evidencia': uri})
            break

    # ── Bots maliciosos ──
    for bot in BOTS_CONOCIDOS:
        if bot in ua:
            ataques.append({'tipo': 'Bot Malicioso', 'score': 60, 'evidencia': f'UA: {ua[:80]}'})
            break

    # ── Honeypot ──
    for honeypot_uri in HONEYPOT_URIS:
        if honeypot_uri in uri.lower():
            ataques.append({'tipo': 'Honeypot Trigger', 'score': 65, 'evidencia': uri})
            break

    # ── Brute Force (detectado por tipo original) ──
    if 'brute' in tipo_orig or 'fuerza_bruta' in tipo_orig or 'login' in uri.lower():
        if metodo == 'POST':
            ataques.append({'tipo': 'Fuerza Bruta', 'score': 70, 'evidencia': f'{metodo} {uri}'})

    # ── Rate Limit ──
    if 'rate' in tipo_orig or 'limit' in tipo_orig or 'flood' in tipo_orig:
        ataques.append({'tipo': 'Rate Limit Abuse', 'score': 55, 'evidencia': tipo_orig})

    # ── Si hay ban, aumentar severidad ──
    if log_entry.get('baneado'):
        for ataque in ataques:
            ataque['score'] = min(100, ataque['score'] + 15)

    # Si no se detectó ningún ataque específico
    if not ataques:
        # Revisar severidad original del log
        severidad = log_entry.get('severidad', '').upper()
        if severidad in ('CRITICAL', 'CRITICO', 'EMERGENCIA'):
            ataques.append({'tipo': 'Alerta Crítica', 'score': 80, 'evidencia': tipo_orig})
        elif severidad in ('ERROR', 'HIGH', 'ALTO'):
            ataques.append({'tipo': 'Alerta Alta', 'score': 55, 'evidencia': tipo_orig})
        elif severidad in ('WARNING', 'WARN', 'MEDIO'):
            ataques.append({'tipo': 'Sospechoso', 'score': 35, 'evidencia': tipo_orig})
        else:
            ataques.append({'tipo': 'Tráfico Normal', 'score': 5, 'evidencia': ''})

    return ataques


def calcular_score_riesgo(ataques_detectados):
    """
    Calcula score de riesgo global (0-100) basado en todos los ataques.
    """
    if not ataques_detectados:
        return 0

    scores = [a['score'] for ataque_list in ataques_detectados for a in ataque_list]
    if not scores:
        return 0

    # Score ponderado: promedio + bonus por cantidad de ataques críticos
    promedio = sum(scores) / len(scores)
    criticos = sum(1 for s in scores if s >= 70)
    bonus = min(20, criticos * 2)

    return min(100, int(promedio + bonus))


def clasificar_severidad(score):
    """Clasifica la severidad según el score."""
    if score >= 75:
        return 'CRITICAL'
    elif score >= 50:
        return 'HIGH'
    elif score >= 30:
        return 'MEDIUM'
    elif score >= 15:
        return 'LOW'
    else:
        return 'INFO'


def analizar_logs_completo(logs_parseados):
    """
    Realiza análisis completo de los logs parseados.
    Retorna resumen con métricas, top IPs, top URIs, tipos de ataques, etc.
    """
    if not logs_parseados:
        return _resultado_vacio()

    # Contadores
    ips_counter = Counter()
    uris_counter = Counter()
    tipos_ataque_counter = Counter()
    severidades_counter = Counter()
    os_counter = Counter()
    browser_counter = Counter()
    ips_ataques = defaultdict(list)
    timeline = defaultdict(lambda: Counter()) # Cambiado a dict de contadores
    ips_baneadas = set()

    todos_ataques = []
    amenazas = []

    from analyzer.parser import extraer_user_agent_info

    for log in logs_parseados:
        ip = log.get('ip', '0.0.0.0')
        uri = log.get('uri', '/')
        ua = log.get('user_agent', '')

        # Contar IPs y URIs
        ips_counter[ip] += 1
        uris_counter[uri] += 1

        # Detección de ataques
        ataques = detectar_tipo_ataque(log)
        todos_ataques.append(ataques)

        for ataque in ataques:
            tipos_ataque_counter[ataque['tipo']] += 1
            ips_ataques[ip].append(ataque)

            if ataque['score'] >= 50:
                amenazas.append({
                    'ip': ip,
                    'tipo': ataque['tipo'],
                    'score': ataque['score'],
                    'severidad': clasificar_severidad(ataque['score']),
                    'uri': uri,
                    'fecha': log.get('fecha', ''),
                    'evidencia': ataque['evidencia'],
                    'metodo': log.get('metodo', ''),
                    'user_agent': ua[:100]
                })

        # Severidad
        for ataque in ataques:
            severidades_counter[clasificar_severidad(ataque['score'])] += 1

        # User Agent info
        ua_info = extraer_user_agent_info(ua)
        os_counter[ua_info['os']] += 1
        browser_counter[ua_info['browser']] += 1

        # Timeline (por hora y severidad)
        fecha = log.get('fecha', '')
        if fecha and len(fecha) >= 13:
            hora = fecha[:13]  # YYYY-MM-DD HH
            # Obtener severidad máxima de esta línea
            max_score = max(a['score'] for a in ataques) if ataques else 0
            sev = clasificar_severidad(max_score)
            timeline[hora][sev] += 1
            timeline[hora]['TOTAL'] += 1

        # IPs baneadas
        if log.get('baneado'):
            ips_baneadas.add(ip)

    # Score global de riesgo
    score_riesgo = calcular_score_riesgo(todos_ataques)
    nivel_riesgo = 'BAJO' if score_riesgo < 30 else 'MEDIO' if score_riesgo < 60 else 'ALTO'

    # Lista completa de IPs con score
    top_ips = []
    for ip, count in ips_counter.most_common():
        ip_scores = [a['score'] for a in ips_ataques.get(ip, [])]
        ip_score = max(ip_scores) if ip_scores else 0
        ip_tipos = list(set(a['tipo'] for a in ips_ataques.get(ip, [])))
        top_ips.append({
            'ip': ip,
            'count': count,
            'score': ip_score,
            'severidad': clasificar_severidad(ip_score),
            'tipos': ip_tipos,
            'baneada': ip in ips_baneadas
        })

    # Lista completa de URIs
    top_uris = [{'uri': uri, 'count': count} for uri, count in uris_counter.most_common()]

    # Tipos de ataque
    tipos_ataque = [{'tipo': tipo, 'count': count} for tipo, count in tipos_ataque_counter.most_common(15)]

    # Timeline ordenada con desglose
    timeline_sorted = sorted(timeline.items())
    timeline_data = []
    for hora, counts in timeline_sorted:
        timeline_data.append({
            'hora': hora,
            'eventos': counts['TOTAL'],
            'CRITICAL': counts['CRITICAL'],
            'HIGH': counts['HIGH'],
            'MEDIUM': counts['MEDIUM'],
            'LOW': counts['LOW'] + counts['INFO']
        })

    # OS y Browsers
    os_data = [{'os': os_name, 'count': count} for os_name, count in os_counter.most_common(10)]
    browsers_data = [{'browser': browser, 'count': count} for browser, count in browser_counter.most_common(10)]

    # Perfil de atacantes
    perfiles_atacantes = []
    for ip_info in top_ips[:10]:
        if ip_info['score'] >= 40:
            perfiles_atacantes.append({
                'ip': ip_info['ip'],
                'score_riesgo': ip_info['score'],
                'total_requests': ip_info['count'],
                'tipos_ataque': ip_info['tipos'],
                'severidad': ip_info['severidad'],
                'baneada': ip_info['baneada'],
                'clasificacion': _clasificar_atacante(ip_info)
            })

    # Amenazas ordenadas por score
    amenazas.sort(key=lambda x: x['score'], reverse=True)

    return {
        'resumen': {
            'total_logs': len(logs_parseados),
            'total_amenazas': len(amenazas),
            'score_riesgo': score_riesgo,
            'nivel_riesgo': nivel_riesgo,
            'ips_unicas': len(ips_counter),
            'uris_unicas': len(uris_counter),
            'ips_baneadas': len(ips_baneadas),
        },
        'amenazas': amenazas[:100],  # Top 100 amenazas
        'top_ips': top_ips,
        'top_uris': top_uris,
        'tipos_ataque': tipos_ataque,
        'severidades': dict(severidades_counter),
        'timeline': timeline_data,
        'os_data': os_data,
        'browsers_data': browsers_data,
        'perfiles_atacantes': perfiles_atacantes,
    }


def _clasificar_atacante(ip_info):
    """Clasifica el perfil del atacante basado en su actividad."""
    tipos = ip_info.get('tipos', [])
    score = ip_info.get('score', 0)
    count = ip_info.get('count', 0)

    if score >= 80 and count > 50:
        return 'APT (Amenaza Persistente Avanzada)'
    elif 'SQL Injection' in tipos and 'XSS' in tipos:
        return 'Scanner Automatizado'
    elif 'Bot Malicioso' in tipos:
        return 'Bot / Script Automatizado'
    elif 'Fuerza Bruta' in tipos:
        return 'Atacante de Fuerza Bruta'
    elif 'Reconocimiento' in tipos:
        return 'Reconocimiento / Enumeración'
    elif score >= 60:
        return 'Atacante Activo'
    else:
        return 'Actividad Sospechosa'


def _resultado_vacio():
    """Retorna un resultado vacío."""
    return {
        'resumen': {
            'total_logs': 0,
            'total_amenazas': 0,
            'score_riesgo': 0,
            'nivel_riesgo': 'BAJO',
            'ips_unicas': 0,
            'uris_unicas': 0,
            'ips_baneadas': 0,
        },
        'amenazas': [],
        'top_ips': [],
        'top_uris': [],
        'tipos_ataque': [],
        'severidades': {},
        'timeline': [],
        'os_data': [],
        'browsers_data': [],
        'perfiles_atacantes': [],
    }
