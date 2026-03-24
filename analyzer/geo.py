"""
VORTEX Security Intelligence - Geolocalización de IPs
Localiza IPs geográficamente con fallback offline.
"""

import json
import random
import hashlib


# ═══════════════════════════════════════════════════════════════
# BASE DE DATOS MOCK DE GEOLOCALIZACIÓN
# Para uso offline con ubicaciones realistas
# ═══════════════════════════════════════════════════════════════

GEOIP_MOCK = {
    # Rango → País, Ciudad, Lat, Lng
    '1.': {'pais': 'Australia', 'ciudad': 'Sydney', 'codigo': 'AU', 'lat': -33.8688, 'lng': 151.2093},
    '2.': {'pais': 'Francia', 'ciudad': 'París', 'codigo': 'FR', 'lat': 48.8566, 'lng': 2.3522},
    '5.': {'pais': 'Alemania', 'ciudad': 'Berlín', 'codigo': 'DE', 'lat': 52.5200, 'lng': 13.4050},
    '8.': {'pais': 'Estados Unidos', 'ciudad': 'Los Ángeles', 'codigo': 'US', 'lat': 34.0522, 'lng': -118.2437},
    '14.': {'pais': 'Japón', 'ciudad': 'Tokio', 'codigo': 'JP', 'lat': 35.6762, 'lng': 139.6503},
    '23.': {'pais': 'Estados Unidos', 'ciudad': 'Nueva York', 'codigo': 'US', 'lat': 40.7128, 'lng': -74.0060},
    '31.': {'pais': 'Países Bajos', 'ciudad': 'Ámsterdam', 'codigo': 'NL', 'lat': 52.3676, 'lng': 4.9041},
    '37.': {'pais': 'Turquía', 'ciudad': 'Estambul', 'codigo': 'TR', 'lat': 41.0082, 'lng': 28.9784},
    '41.': {'pais': 'Egipto', 'ciudad': 'El Cairo', 'codigo': 'EG', 'lat': 30.0444, 'lng': 31.2357},
    '45.': {'pais': 'Canadá', 'ciudad': 'Toronto', 'codigo': 'CA', 'lat': 43.6532, 'lng': -79.3832},
    '46.': {'pais': 'Rusia', 'ciudad': 'Moscú', 'codigo': 'RU', 'lat': 55.7558, 'lng': 37.6173},
    '49.': {'pais': 'Ucrania', 'ciudad': 'Kiev', 'codigo': 'UA', 'lat': 50.4501, 'lng': 30.5234},
    '51.': {'pais': 'Reino Unido', 'ciudad': 'Londres', 'codigo': 'GB', 'lat': 51.5074, 'lng': -0.1278},
    '58.': {'pais': 'China', 'ciudad': 'Shanghái', 'codigo': 'CN', 'lat': 31.2304, 'lng': 121.4737},
    '61.': {'pais': 'Australia', 'ciudad': 'Melbourne', 'codigo': 'AU', 'lat': -37.8136, 'lng': 144.9631},
    '64.': {'pais': 'Canadá', 'ciudad': 'Vancouver', 'codigo': 'CA', 'lat': 49.2827, 'lng': -123.1207},
    '66.': {'pais': 'Estados Unidos', 'ciudad': 'Chicago', 'codigo': 'US', 'lat': 41.8781, 'lng': -87.6298},
    '72.': {'pais': 'Estados Unidos', 'ciudad': 'Dallas', 'codigo': 'US', 'lat': 32.7767, 'lng': -96.7970},
    '77.': {'pais': 'Rusia', 'ciudad': 'San Petersburgo', 'codigo': 'RU', 'lat': 59.9343, 'lng': 30.3351},
    '78.': {'pais': 'España', 'ciudad': 'Madrid', 'codigo': 'ES', 'lat': 40.4168, 'lng': -3.7038},
    '80.': {'pais': 'Italia', 'ciudad': 'Roma', 'codigo': 'IT', 'lat': 41.9028, 'lng': 12.4964},
    '82.': {'pais': 'Alemania', 'ciudad': 'Múnich', 'codigo': 'DE', 'lat': 48.1351, 'lng': 11.5820},
    '85.': {'pais': 'Francia', 'ciudad': 'Lyon', 'codigo': 'FR', 'lat': 45.7640, 'lng': 4.8357},
    '89.': {'pais': 'Turquía', 'ciudad': 'Ankara', 'codigo': 'TR', 'lat': 39.9334, 'lng': 32.8597},
    '91.': {'pais': 'India', 'ciudad': 'Mumbai', 'codigo': 'IN', 'lat': 19.0760, 'lng': 72.8777},
    '95.': {'pais': 'Rusia', 'ciudad': 'Novosibirsk', 'codigo': 'RU', 'lat': 55.0084, 'lng': 82.9357},
    '101.': {'pais': 'India', 'ciudad': 'Delhi', 'codigo': 'IN', 'lat': 28.7041, 'lng': 77.1025},
    '103.': {'pais': 'Indonesia', 'ciudad': 'Yakarta', 'codigo': 'ID', 'lat': -6.2088, 'lng': 106.8456},
    '104.': {'pais': 'Estados Unidos', 'ciudad': 'San Francisco', 'codigo': 'US', 'lat': 37.7749, 'lng': -122.4194},
    '110.': {'pais': 'China', 'ciudad': 'Pekín', 'codigo': 'CN', 'lat': 39.9042, 'lng': 116.4074},
    '112.': {'pais': 'China', 'ciudad': 'Guangzhou', 'codigo': 'CN', 'lat': 23.1291, 'lng': 113.2644},
    '115.': {'pais': 'Vietnam', 'ciudad': 'Hanói', 'codigo': 'VN', 'lat': 21.0278, 'lng': 105.8342},
    '118.': {'pais': 'Corea del Sur', 'ciudad': 'Seúl', 'codigo': 'KR', 'lat': 37.5665, 'lng': 126.9780},
    '125.': {'pais': 'Japón', 'ciudad': 'Osaka', 'codigo': 'JP', 'lat': 34.6937, 'lng': 135.5023},
    '128.': {'pais': 'Estados Unidos', 'ciudad': 'Boston', 'codigo': 'US', 'lat': 42.3601, 'lng': -71.0589},
    '130.': {'pais': 'Suecia', 'ciudad': 'Estocolmo', 'codigo': 'SE', 'lat': 59.3293, 'lng': 18.0686},
    '134.': {'pais': 'Australia', 'ciudad': 'Brisbane', 'codigo': 'AU', 'lat': -27.4698, 'lng': 153.0251},
    '138.': {'pais': 'Singapur', 'ciudad': 'Singapur', 'codigo': 'SG', 'lat': 1.3521, 'lng': 103.8198},
    '141.': {'pais': 'Canadá', 'ciudad': 'Montreal', 'codigo': 'CA', 'lat': 45.5017, 'lng': -73.5673},
    '143.': {'pais': 'Brasil', 'ciudad': 'São Paulo', 'codigo': 'BR', 'lat': -23.5505, 'lng': -46.6333},
    '145.': {'pais': 'Sudáfrica', 'ciudad': 'Johannesburgo', 'codigo': 'ZA', 'lat': -26.2041, 'lng': 28.0473},
    '150.': {'pais': 'Corea del Sur', 'ciudad': 'Busan', 'codigo': 'KR', 'lat': 35.1796, 'lng': 129.0756},
    '154.': {'pais': 'Nigeria', 'ciudad': 'Lagos', 'codigo': 'NG', 'lat': 6.5244, 'lng': 3.3792},
    '156.': {'pais': 'China', 'ciudad': 'Shenzhen', 'codigo': 'CN', 'lat': 22.5431, 'lng': 114.0579},
    '160.': {'pais': 'Brasil', 'ciudad': 'Río de Janeiro', 'codigo': 'BR', 'lat': -22.9068, 'lng': -43.1729},
    '162.': {'pais': 'Estados Unidos', 'ciudad': 'Miami', 'codigo': 'US', 'lat': 25.7617, 'lng': -80.1918},
    '168.': {'pais': 'México', 'ciudad': 'Guadalajara', 'codigo': 'MX', 'lat': 20.6597, 'lng': -103.3496},
    '170.': {'pais': 'Colombia', 'ciudad': 'Bogotá', 'codigo': 'CO', 'lat': 4.7110, 'lng': -74.0721},
    '172.': {'pais': 'Interno', 'ciudad': 'Red Privada', 'codigo': 'LAN', 'lat': 19.4326, 'lng': -99.1332},
    '176.': {'pais': 'Irán', 'ciudad': 'Teherán', 'codigo': 'IR', 'lat': 35.6892, 'lng': 51.3890},
    '178.': {'pais': 'Rusia', 'ciudad': 'Ekaterimburgo', 'codigo': 'RU', 'lat': 56.8389, 'lng': 60.6057},
    '180.': {'pais': 'Pakistán', 'ciudad': 'Karachi', 'codigo': 'PK', 'lat': 24.8607, 'lng': 67.0011},
    '185.': {'pais': 'Países Bajos', 'ciudad': 'Róterdam', 'codigo': 'NL', 'lat': 51.9244, 'lng': 4.4777},
    '188.': {'pais': 'Arabia Saudita', 'ciudad': 'Riad', 'codigo': 'SA', 'lat': 24.7136, 'lng': 46.6753},
    '190.': {'pais': 'Argentina', 'ciudad': 'Buenos Aires', 'codigo': 'AR', 'lat': -34.6037, 'lng': -58.3816},
    '192.': {'pais': 'Interno', 'ciudad': 'Red Privada', 'codigo': 'LAN', 'lat': 19.4326, 'lng': -99.1332},
    '195.': {'pais': 'Ucrania', 'ciudad': 'Járkov', 'codigo': 'UA', 'lat': 49.9935, 'lng': 36.2304},
    '197.': {'pais': 'Kenia', 'ciudad': 'Nairobi', 'codigo': 'KE', 'lat': -1.2921, 'lng': 36.8219},
    '200.': {'pais': 'México', 'ciudad': 'Ciudad de México', 'codigo': 'MX', 'lat': 19.4326, 'lng': -99.1332},
    '201.': {'pais': 'México', 'ciudad': 'Monterrey', 'codigo': 'MX', 'lat': 25.6866, 'lng': -100.3161},
    '202.': {'pais': 'Tailandia', 'ciudad': 'Bangkok', 'codigo': 'TH', 'lat': 13.7563, 'lng': 100.5018},
    '203.': {'pais': 'Hong Kong', 'ciudad': 'Hong Kong', 'codigo': 'HK', 'lat': 22.3193, 'lng': 114.1694},
    '206.': {'pais': 'Estados Unidos', 'ciudad': 'Seattle', 'codigo': 'US', 'lat': 47.6062, 'lng': -122.3321},
    '209.': {'pais': 'Estados Unidos', 'ciudad': 'Atlanta', 'codigo': 'US', 'lat': 33.7490, 'lng': -84.3880},
    '210.': {'pais': 'Japón', 'ciudad': 'Nagoya', 'codigo': 'JP', 'lat': 35.1815, 'lng': 136.9066},
    '212.': {'pais': 'Turquía', 'ciudad': 'Esmirna', 'codigo': 'TR', 'lat': 38.4237, 'lng': 27.1428},
    '213.': {'pais': 'España', 'ciudad': 'Barcelona', 'codigo': 'ES', 'lat': 41.3874, 'lng': 2.1686},
    '216.': {'pais': 'Estados Unidos', 'ciudad': 'Denver', 'codigo': 'US', 'lat': 39.7392, 'lng': -104.9903},
    '217.': {'pais': 'Alemania', 'ciudad': 'Frankfurt', 'codigo': 'DE', 'lat': 50.1109, 'lng': 8.6821},
    '220.': {'pais': 'Corea del Sur', 'ciudad': 'Incheon', 'codigo': 'KR', 'lat': 37.4563, 'lng': 126.7052},
    '223.': {'pais': 'China', 'ciudad': 'Chengdu', 'codigo': 'CN', 'lat': 30.5728, 'lng': 104.0668},
}

# Servidor base (México)
SERVIDOR_BASE = {
    'pais': 'México',
    'ciudad': 'Ciudad de México',
    'codigo': 'MX',
    'lat': 19.4326,
    'lng': -99.1332
}


def geolocalizar_ip(ip):
    """
    Geolocaliza una IP usando la base mock.
    Genera ubicaciones deterministas basadas en el hash de la IP.
    """
    if not ip or ip in ('0.0.0.0', '127.0.0.1', 'localhost'):
        return {**SERVIDOR_BASE, 'ip': ip}

    # IPs privadas
    if ip.startswith(('10.', '192.168.', '172.16.', '172.17.', '172.18.',
                       '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
                       '172.24.', '172.25.', '172.26.', '172.27.', '172.28.',
                       '172.29.', '172.30.', '172.31.')):
        return {**SERVIDOR_BASE, 'ip': ip}

    # Buscar en la base mock por prefijo
    for prefijo, datos in GEOIP_MOCK.items():
        if ip.startswith(prefijo):
            # Agregar variación basada en el hash de la IP
            ip_hash = int(hashlib.md5(ip.encode()).hexdigest()[:8], 16)
            lat_offset = (ip_hash % 100 - 50) * 0.01
            lng_offset = ((ip_hash >> 8) % 100 - 50) * 0.01
            return {
                'pais': datos['pais'],
                'ciudad': datos['ciudad'],
                'codigo': datos['codigo'],
                'lat': datos['lat'] + lat_offset,
                'lng': datos['lng'] + lng_offset,
                'ip': ip
            }

    # Fallback: generar ubicación basada en hash
    ip_hash = int(hashlib.md5(ip.encode()).hexdigest()[:16], 16)
    ubicaciones_fallback = list(GEOIP_MOCK.values())
    idx = ip_hash % len(ubicaciones_fallback)
    datos = ubicaciones_fallback[idx]

    return {
        'pais': datos['pais'],
        'ciudad': datos['ciudad'],
        'codigo': datos['codigo'],
        'lat': datos['lat'] + (ip_hash % 200 - 100) * 0.005,
        'lng': datos['lng'] + ((ip_hash >> 16) % 200 - 100) * 0.005,
        'ip': ip
    }


def geolocalizar_ip_online(ip):
    """
    Intenta geolocalizar usando API online (ip-api.com).
    Si falla, usa el fallback mock.
    """
    try:
        import urllib.request
        url = f'http://ip-api.com/json/{ip}?fields=status,country,city,countryCode,lat,lon'
        req = urllib.request.Request(url, headers={'User-Agent': 'VORTEX-Security/1.0'})
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode())
            if data.get('status') == 'success':
                return {
                    'pais': data.get('country', 'Desconocido'),
                    'ciudad': data.get('city', 'Desconocido'),
                    'codigo': data.get('countryCode', '??'),
                    'lat': data.get('lat', 0),
                    'lng': data.get('lon', 0),
                    'ip': ip,
                    'online': True
                }
    except Exception:
        pass

    # Fallback a mock
    resultado = geolocalizar_ip(ip)
    resultado['online'] = False
    return resultado


def geolocalizar_multiples_ips(ips, usar_online=False):
    """
    Geolocaliza múltiples IPs.
    Cachea resultados para evitar consultas duplicadas.
    """
    cache = {}
    resultados = []

    for ip in ips:
        if ip not in cache:
            if usar_online:
                cache[ip] = geolocalizar_ip_online(ip)
            else:
                cache[ip] = geolocalizar_ip(ip)
        resultados.append(cache[ip])

    return resultados


def obtener_datos_mapa(top_ips, amenazas):
    """
    Genera datos para el mapa "Ojo de Dios".
    Cada punto tiene: posición, color según severidad, información del ataque.
    """
    puntos = []
    ips_procesadas = set()

    # Procesar top IPs
    for ip_info in top_ips:
        ip = ip_info.get('ip', '')
        if ip in ips_procesadas:
            continue
        ips_procesadas.add(ip)

        geo = geolocalizar_ip(ip)
        score = ip_info.get('score', 0)

        # Determinar color según score
        if score >= 70:
            color = 'rojo'
        elif score >= 40:
            color = 'amarillo'
        else:
            color = 'azul'

        puntos.append({
            'ip': ip,
            'lat': geo['lat'],
            'lng': geo['lng'],
            'pais': geo['pais'],
            'ciudad': geo['ciudad'],
            'codigo': geo['codigo'],
            'score': score,
            'color': color,
            'count': ip_info.get('count', 1),
            'tipos': ip_info.get('tipos', []),
            'severidad': ip_info.get('severidad', 'INFO'),
            'baneada': ip_info.get('baneada', False)
        })

    return {
        'servidor_base': SERVIDOR_BASE,
        'puntos': puntos,
        'total_origenes': len(puntos)
    }
