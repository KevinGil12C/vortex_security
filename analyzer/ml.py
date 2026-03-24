"""
VORTEX Security Intelligence - Machine Learning
Detección de anomalías con IsolationForest.
"""

import numpy as np
from collections import Counter, defaultdict


def preparar_features(logs_parseados):
    """
    Convierte logs parseados en features numéricas para ML.
    Features:
    - frecuencia_ip: cuántas veces aparece la IP
    - longitud_uri: largo del URI
    - es_post: si el método es POST
    - hora: hora del evento (0-23)
    - tiene_params: si el URI tiene parámetros
    - longitud_ua: largo del user agent
    - uri_profundidad: profundidad del path
    - chars_especiales: cantidad de caracteres especiales en URI
    """
    if not logs_parseados:
        return np.array([]), [], []

    # Contar frecuencia de IPs
    ip_freq = Counter(log.get('ip', '') for log in logs_parseados)

    features = []
    ips = []
    indices_validos = []

    for i, log in enumerate(logs_parseados):
        try:
            ip = log.get('ip', '0.0.0.0')
            uri = log.get('uri', '/')
            metodo = log.get('metodo', 'GET')
            ua = log.get('user_agent', '')
            fecha = log.get('fecha', '')

            # Extraer hora
            hora = 12  # default
            try:
                if len(fecha) >= 13:
                    hora = int(fecha[11:13])
            except (ValueError, IndexError):
                pass

            # Caracteres especiales en URI
            chars_esp = sum(1 for c in uri if c in "';\"<>(){}[]|&$`!%\\")

            feature_vector = [
                ip_freq.get(ip, 1),                    # frecuencia IP
                len(uri),                               # longitud URI
                1 if metodo == 'POST' else 0,           # es POST
                hora,                                    # hora del día
                1 if '?' in uri or '=' in uri else 0,   # tiene parámetros
                len(ua),                                 # longitud UA
                uri.count('/'),                          # profundidad URI
                chars_esp,                               # caracteres especiales
            ]

            features.append(feature_vector)
            ips.append(ip)
            indices_validos.append(i)

        except Exception:
            continue

    if not features:
        return np.array([]), [], []

    return np.array(features), ips, indices_validos


def detectar_anomalias(logs_parseados, contamination=0.1):
    """
    Usa IsolationForest para detectar anomalías en los logs.
    Retorna lista de logs anómalos con información adicional.
    """
    if len(logs_parseados) < 10:
        return {
            'anomalias': [],
            'total_anomalias': 0,
            'mensaje': 'Se necesitan al menos 10 logs para detección de anomalías'
        }

    try:
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
    except ImportError:
        return {
            'anomalias': [],
            'total_anomalias': 0,
            'mensaje': 'sklearn no está instalado. Ejecutar: pip install scikit-learn'
        }

    features, ips, indices_validos = preparar_features(logs_parseados)

    if len(features) < 10:
        return {
            'anomalias': [],
            'total_anomalias': 0,
            'mensaje': 'Insuficientes features para análisis ML'
        }

    try:
        # Normalizar features
        scaler = StandardScaler()
        features_norm = scaler.fit_transform(features)

        # Ajustar contaminación según el tamaño del dataset
        cont = min(contamination, 0.5)
        cont = max(cont, 0.01)

        # Entrenar IsolationForest
        modelo = IsolationForest(
            n_estimators=100,
            contamination=cont,
            random_state=42,
            n_jobs=-1
        )
        predicciones = modelo.fit_predict(features_norm)
        scores = modelo.decision_function(features_norm)

        # Extraer anomalías (predicción == -1)
        anomalias = []
        for i, (pred, score) in enumerate(zip(predicciones, scores)):
            if pred == -1:
                idx_original = indices_validos[i]
                log = logs_parseados[idx_original]
                anomalia_score = max(0, min(100, int((1 - (score + 0.5)) * 100)))

                anomalias.append({
                    'ip': log.get('ip', ''),
                    'uri': log.get('uri', ''),
                    'fecha': log.get('fecha', ''),
                    'metodo': log.get('metodo', ''),
                    'user_agent': log.get('user_agent', '')[:100],
                    'anomalia_score': anomalia_score,
                    'tipo': 'Zero-Day IA',
                    'descripcion': _describir_anomalia(features[i], log),
                    'severidad': 'CRITICAL' if anomalia_score >= 80 else 'HIGH' if anomalia_score >= 60 else 'MEDIUM'
                })

        # Ordenar por score
        anomalias.sort(key=lambda x: x['anomalia_score'], reverse=True)

        return {
            'anomalias': anomalias[:50],
            'total_anomalias': len(anomalias),
            'total_analizados': len(features),
            'porcentaje_anomalias': round(len(anomalias) / len(features) * 100, 2) if features.any() else 0,
            'mensaje': f'Se detectaron {len(anomalias)} anomalías de {len(features)} registros analizados'
        }

    except Exception as e:
        return {
            'anomalias': [],
            'total_anomalias': 0,
            'mensaje': f'Error en análisis ML: {str(e)}'
        }


def _describir_anomalia(features_vector, log):
    """Genera descripción de por qué un log es anómalo."""
    descripciones = []

    freq_ip = features_vector[0]
    len_uri = features_vector[1]
    chars_esp = features_vector[7]
    profundidad = features_vector[6]

    if freq_ip > 50:
        descripciones.append(f'Alta frecuencia de IP ({int(freq_ip)} requests)')
    elif freq_ip == 1:
        descripciones.append('IP única (una sola petición)')

    if len_uri > 200:
        descripciones.append(f'URI inusualmente largo ({int(len_uri)} chars)')

    if chars_esp > 5:
        descripciones.append(f'Muchos caracteres especiales en URI ({int(chars_esp)})')

    if profundidad > 5:
        descripciones.append(f'Path muy profundo ({int(profundidad)} niveles)')

    if not descripciones:
        descripciones.append('Patrón fuera de distribución normal')

    return ' | '.join(descripciones)


def detectar_clusters_ip(logs_parseados):
    """
    Agrupa IPs por comportamiento similar para detectar botnets.
    """
    if len(logs_parseados) < 5:
        return {'clusters': [], 'mensaje': 'Insuficientes datos para clustering'}

    # Agrupar por IP
    ip_data = defaultdict(lambda: {
        'uris': [], 'metodos': [], 'user_agents': set(),
        'horas': [], 'count': 0
    })

    for log in logs_parseados:
        ip = log.get('ip', '')
        ip_data[ip]['uris'].append(log.get('uri', ''))
        ip_data[ip]['metodos'].append(log.get('metodo', ''))
        ip_data[ip]['user_agents'].add(log.get('user_agent', '')[:50])
        ip_data[ip]['count'] += 1
        try:
            hora = int(log.get('fecha', '')[11:13])
            ip_data[ip]['horas'].append(hora)
        except (ValueError, IndexError):
            pass

    # Detectar clusters por UA similar
    ua_groups = defaultdict(list)
    for ip, data in ip_data.items():
        for ua in data['user_agents']:
            ua_key = ua[:30]  # Agrupar por prefijo de UA
            ua_groups[ua_key].append(ip)

    clusters = []
    for ua_prefix, ips_en_cluster in ua_groups.items():
        if len(ips_en_cluster) >= 3:
            total_reqs = sum(ip_data[ip]['count'] for ip in ips_en_cluster)
            clusters.append({
                'user_agent_comun': ua_prefix,
                'ips': list(set(ips_en_cluster))[:20],
                'total_ips': len(set(ips_en_cluster)),
                'total_requests': total_reqs,
                'posible_botnet': len(ips_en_cluster) >= 5,
                'riesgo': 'ALTO' if len(ips_en_cluster) >= 5 else 'MEDIO'
            })

    clusters.sort(key=lambda x: x['total_ips'], reverse=True)

    return {
        'clusters': clusters[:10],
        'total_clusters': len(clusters),
        'mensaje': f'Se detectaron {len(clusters)} clusters de IPs'
    }
