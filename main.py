"""
╔══════════════════════════════════════════════════════════════╗
║   VORTEX Security Intelligence - Tactical Analysis Core      ║
║   Sistema SIEM/IDS con IA Local                              ║
║   Punto de entrada principal                                  ║
╚══════════════════════════════════════════════════════════════╝
"""

import os
import sys
import json
import eel
import threading
from datetime import datetime
from dotenv import load_dotenv

# Cargar configuración
load_dotenv()

# Configuración desde .env
VOICE_ENABLED = os.getenv('VOICE_ENABLED', 'true').lower() == 'true'
MODEL_NAME = os.getenv('MODEL_NAME', 'Qwen/Qwen1.5-0.5B-Chat')
LOG_PATH = os.getenv('LOG_PATH', 'writable/logs/security_audit.log')

# Inicializar Eel
eel.init('web')

# ═══════════════════════════════════════════════════════════════
# ESTADO GLOBAL
# ═══════════════════════════════════════════════════════════════

estado_global = {
    'analisis': None,
    'logs_cargados': [],
    'voz_habilitada': VOICE_ENABLED,
    'ia_cargada': False,
    'analizando': False,
}

# Instancias globales inicializadas lazy
_voz = None
_ia = None


def obtener_voz():
    global _voz
    if _voz is None:
        from voice.tts import obtener_voz as _get_voz
        _voz = _get_voz(VOICE_ENABLED)
    return _voz


def obtener_ia():
    global _ia
    if _ia is None:
        from ai.llm import obtener_ia as _get_ia
        _ia = _get_ia(MODEL_NAME)
    return _ia


# ═══════════════════════════════════════════════════════════════
# FUNCIONES EEL EXPUESTAS AL FRONTEND
# ═══════════════════════════════════════════════════════════════

@eel.expose
def analizar_logs(texto_logs=None):
    """
    Función principal de análisis.
    Si texto_logs es None, lee del archivo configurado en .env
    """
    estado_global['analizando'] = True

    try:
        from analyzer.parser import parsear_logs, leer_archivo_log
        from analyzer.detector import analizar_logs_completo
        from analyzer.ml import detectar_anomalias, detectar_clusters_ip
        from analyzer.geo import obtener_datos_mapa

        # Obtener logs
        if texto_logs:
            resultado_parser = parsear_logs(texto_logs)
        else:
            resultado_parser = leer_archivo_log(LOG_PATH)

        logs = resultado_parser.get('logs', [])
        estado_global['logs_cargados'] = logs

        if not logs:
            estado_global['analizando'] = False
            return json.dumps({
                'error': 'No se encontraron logs para analizar',
                'parser': resultado_parser
            }, ensure_ascii=False)

        # Voz: inicio análisis
        voz = obtener_voz()
        voz.evento_inicio_analisis(len(logs))

        # Análisis de detección
        analisis = analizar_logs_completo(logs)

        # Machine Learning - Anomalías
        ml_resultado = detectar_anomalias(logs)
        analisis['anomalias'] = ml_resultado

        # Clustering de IPs
        clusters = detectar_clusters_ip(logs)
        analisis['clusters'] = clusters

        # Geolocalización para mapa
        datos_mapa = obtener_datos_mapa(analisis.get('top_ips', []), analisis.get('amenazas', []))
        analisis['geo_data'] = datos_mapa

        # Info del parser
        analisis['parser_info'] = {
            'total_parseados': resultado_parser.get('total_parseados', 0),
            'total_fallidos': resultado_parser.get('total_fallidos', 0),
        }

        # Guardar estado
        estado_global['analisis'] = analisis

        # Voz: detecciones críticas
        amenazas_criticas = [a for a in analisis.get('amenazas', []) if a.get('score', 0) >= 80]
        if amenazas_criticas:
            primera = amenazas_criticas[0]
            voz.evento_deteccion_critica(primera.get('tipo', ''), primera.get('ip', ''))

        # Voz: resumen final
        voz.evento_resumen_final(analisis.get('resumen', {}))

        estado_global['analizando'] = False
        return json.dumps(analisis, ensure_ascii=False, default=str)

    except Exception as e:
        estado_global['analizando'] = False
        return json.dumps({'error': str(e)}, ensure_ascii=False)


@eel.expose
def analizar_archivo(ruta_archivo):
    """Analiza un archivo de log específico."""
    try:
        with open(ruta_archivo, 'r', encoding='utf-8', errors='ignore') as f:
            contenido = f.read()
        return analizar_logs(contenido)
    except Exception as e:
        return json.dumps({'error': f'Error al leer archivo: {str(e)}'}, ensure_ascii=False)


@eel.expose
def generar_reporte_pdf():
    """Genera un reporte PDF del último análisis."""
    if not estado_global['analisis']:
        return json.dumps({'error': 'No hay análisis disponible. Ejecuta un análisis primero.'}, ensure_ascii=False)

    try:
        from reports.pdf_generator import generar_reporte_pdf as _gen_pdf

        analisis = estado_global['analisis']

        # Agregar informe IA si está disponible
        ia = obtener_ia()
        if not analisis.get('informe_ia'):
            informe = ia.generar_reporte_ia(analisis)
            analisis['informe_ia'] = informe

        resultado = _gen_pdf(analisis)

        # Voz
        if resultado.get('exito'):
            obtener_voz().evento_reporte_generado()

        return json.dumps(resultado, ensure_ascii=False)

    except Exception as e:
        return json.dumps({'error': str(e)}, ensure_ascii=False)


@eel.expose
def toggle_voz():
    """Activa/desactiva el sistema de voz."""
    voz = obtener_voz()
    nuevo_estado = voz.toggle()
    estado_global['voz_habilitada'] = nuevo_estado
    return json.dumps({'habilitado': nuevo_estado})


@eel.expose
def obtener_datos_dashboard():
    """Retorna los datos del dashboard actual."""
    if estado_global['analisis']:
        return json.dumps(estado_global['analisis'], ensure_ascii=False, default=str)
    return json.dumps({'error': 'No hay datos de análisis disponibles.'}, ensure_ascii=False)


@eel.expose
def generar_reporte_ia(usar_reglas=False):
    """
    Genera un reporte. 
    usar_reglas=True -> Motor de Reglas (Rápido)
    usar_reglas=False -> Motor LLM (Lento/IA)
    """
    if not estado_global['analisis']:
        return json.dumps({'error': 'No hay análisis disponible.'}, ensure_ascii=False)

    try:
        ia = obtener_ia()
        informe = ia.generar_reporte_ia(estado_global['analisis'], force_rules=usar_reglas)
        estado_global['analisis']['informe_ia'] = informe
        return json.dumps(informe, ensure_ascii=False)
    except Exception as e:
        return json.dumps({'error': str(e)}, ensure_ascii=False)


@eel.expose
def cargar_modelo_ia():
    """Carga el modelo de IA (puede demorar)."""
    try:
        ia = obtener_ia()
        exito = ia.cargar_modelo()
        estado_global['ia_cargada'] = exito
        return json.dumps({
            'cargado': exito,
            'modelo': ia.modelo_nombre,
            'error': ia.error_msg if not exito else ''
        }, ensure_ascii=False)
    except Exception as e:
        return json.dumps({'error': str(e)}, ensure_ascii=False)


@eel.expose
def obtener_estado():
    """Retorna el estado actual del sistema."""
    return json.dumps({
        'voz_habilitada': estado_global['voz_habilitada'],
        'ia_cargada': estado_global['ia_cargada'],
        'logs_cargados': len(estado_global['logs_cargados']),
        'tiene_analisis': estado_global['analisis'] is not None,
        'analizando': estado_global['analizando'],
        'log_path': LOG_PATH,
    }, ensure_ascii=False)


@eel.expose
def verificar_archivo_log():
    """Verifica si el archivo de log existe."""
    existe = os.path.isfile(LOG_PATH)
    tamano = 0
    if existe:
        tamano = os.path.getsize(LOG_PATH)
    return json.dumps({
        'existe': existe,
        'ruta': LOG_PATH,
        'tamano': tamano,
        'tamano_legible': _formato_tamano(tamano)
    }, ensure_ascii=False)


@eel.expose
def leer_logs_archivo():
    """Lee el contenido del archivo de logs configurado."""
    try:
        if os.path.isfile(LOG_PATH):
            with open(LOG_PATH, 'r', encoding='utf-8', errors='ignore') as f:
                contenido = f.read()
            lineas = contenido.strip().split('\n') if contenido.strip() else []
            return json.dumps({
                'contenido': contenido,
                'total_lineas': len(lineas),
                'exito': True
            }, ensure_ascii=False)
        else:
            return json.dumps({
                'contenido': '',
                'total_lineas': 0,
                'exito': False,
                'error': f'Archivo no encontrado: {LOG_PATH}'
            }, ensure_ascii=False)
    except Exception as e:
        return json.dumps({'error': str(e), 'exito': False}, ensure_ascii=False)


@eel.expose
def abrir_reporte_pdf():
    """Abre el último reporte PDF generado."""
    try:
        reports_dir = os.path.join(os.path.dirname(__file__), 'reports')
        if not os.path.isdir(reports_dir):
            return json.dumps({'error': 'No hay reportes generados.'}, ensure_ascii=False)

        pdfs = [f for f in os.listdir(reports_dir) if f.endswith('.pdf')]
        if not pdfs:
            return json.dumps({'error': 'No hay reportes PDF generados.'}, ensure_ascii=False)

        # Último PDF
        pdfs.sort(reverse=True)
        ruta = os.path.join(reports_dir, pdfs[0])
        os.startfile(ruta)
        return json.dumps({'exito': True, 'archivo': pdfs[0]}, ensure_ascii=False)
    except Exception as e:
        return json.dumps({'error': str(e)}, ensure_ascii=False)


def _formato_tamano(bytes_size):
    """Convierte bytes a formato legible."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.1f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.1f} TB"


# ═══════════════════════════════════════════════════════════════
# INICIO DE LA APLICACIÓN
# ═══════════════════════════════════════════════════════════════

def main():
    """Punto de entrada principal."""
    # Corrección de codificación para Windows (Manejo de caracteres especiales en consola)
    if sys.platform == 'win32':
        try:
            os.system('chcp 65001 > nul')
            if hasattr(sys.stdout, 'reconfigure'):
                sys.stdout.reconfigure(encoding='utf-8')
        except:
            pass

    print("********************************************************")
    print("*  VORTEX Security Intelligence                       *")
    print("*  Tactical Analysis Core v1.0                        *")
    print("*  Sistema SIEM/IDS con Inteligencia Artificial       *")
    print("********************************************************")
    print()
    print(f"[+] Configuración cargada:")
    print(f"    Voz: {'Habilitada' if VOICE_ENABLED else 'Deshabilitada'}")
    print(f"    Modelo IA: {MODEL_NAME}")
    print(f"    Ruta logs: {LOG_PATH}")
    print()

    # Iniciar voz
    if VOICE_ENABLED:
        try:
            voz = obtener_voz()
            voz.evento_inicio_sistema()
        except Exception as e:
            print(f"[!] Error al iniciar sistema de voz: {e}")

    print("[+] Iniciando interfaz web...")
    print("[+] Se abrirá el navegador automáticamente...")
    print("[+] Para cerrar: Ctrl+C o usa stop.bat")
    print()

    try:
        eel.start(
            'index.html',
            size=(1400, 900),
            port=8147,
            host='localhost',
            mode='chrome',
            cmdline_args=['--disable-features=TranslateUI']
        )
    except EnvironmentError:
        # Si Chrome no está disponible, intentar con Edge
        try:
            eel.start(
                'index.html',
                size=(1400, 900),
                port=8147,
                host='localhost',
                mode='edge'
            )
        except Exception:
            # Fallback: abrir en navegador por defecto
            eel.start(
                'index.html',
                size=(1400, 900),
                port=8147,
                host='localhost',
                mode='default'
            )


if __name__ == '__main__':
    main()
