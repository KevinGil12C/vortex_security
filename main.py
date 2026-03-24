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
import psutil
import tkinter as tk
from tkinter import filedialog
from datetime import datetime
from dotenv import load_dotenv

# Cargar configuración
load_dotenv()

# Configuración desde .env
VOICE_ENABLED = os.getenv('VOICE_ENABLED', 'true').lower() == 'true'
MODEL_NAME = os.getenv('MODEL_NAME', 'Qwen/Qwen2-1.5B-Instruct')
LOG_PATH = os.getenv('LOG_PATH', 'writable/logs/security_audit.log')

# Inicializar Eel
eel.init('web')

# ═══════════════════════════════════════════════════════════════
# ESTADO GLOBAL
# ═══════════════════════════════════════════════════════════════

estado_global = {
    'analisis': {}, 
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
def generar_reporte_pdf(mapa_b64=None, graficos_b64=None):
    """Genera un reporte PDF con diálogo de guardado."""
    if not estado_global['analisis']:
        return json.dumps({'error': 'No hay análisis para reportar.'}, ensure_ascii=False)

    try:
        from reports.pdf_generator import generar_reporte_pdf as _gen_pdf
        analisis = estado_global['analisis']

        # Diálogo de guardado
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        file_path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("Reporte PDF", "*.pdf")],
            initialfile=f"VORTEX_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
            title="Guardar Reporte de Inteligencia"
        )
        root.destroy()

        if not file_path:
            return json.dumps({'cancelado': True})

        # Generar reporte base
        resultado = _gen_pdf(analisis, mapa_b64=mapa_b64, graficos_b64=graficos_b64)
        
        if resultado.get('exito'):
            # Copiar el archivo generado a la ruta elegida por el usuario
            import shutil
            ruta_original = resultado.get('ruta')
            if ruta_original and os.path.exists(ruta_original):
                shutil.copy2(ruta_original, file_path)
                
                # Auto-Limpieza de archivos temporales (Capturas y PDF base)
                try:
                    rep_dir = str(os.path.dirname(ruta_original))
                    for fn in os.listdir(rep_dir):
                        file_abs = os.path.join(rep_dir, fn)
                        if fn.startswith('vortex_chart_') or fn == 'vortex_map.png':
                            os.remove(file_abs)
                        elif fn == os.path.basename(ruta_original):
                            os.remove(file_abs)
                except Exception as e:
                    print(f"[VORTEX] Info: Cleanup secundario parcial - {str(e)}")
            
            obtener_voz().evento_reporte_generado()
            return json.dumps({
                'exito': True, 
                'archivo': os.path.basename(file_path),
                'path': file_path,
                'msg': f'Reporte guardado en: {file_path}'
            }, ensure_ascii=False)
        
        return json.dumps(resultado, ensure_ascii=False)

    except Exception as e:
        return json.dumps({'error': str(e)}, ensure_ascii=False)
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
def obtener_salud_sistema():
    """Retorna el uso de CPU y RAM del sistema."""
    try:
        cpu = psutil.cpu_percent(interval=None)
        ram = psutil.virtual_memory().percent
        res_ia = "ACTIVO" if estado_global['ia_cargada'] else "MODO LEAN"
        
        return json.dumps({
            'cpu': cpu,
            'ram': ram,
            'modelo': MODEL_NAME,
            'ia_status': res_ia,
            'exito': True
        })
    except:
        return json.dumps({'exito': False})



@eel.expose
def exportar_forense(formato='csv'):
    """Exporta el análisis actual a CSV o JSON eligiendo ruta."""
    if not estado_global['analisis']:
        return json.dumps({'error': 'No hay datos para exportar.'})

    try:
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        
        ext = '.csv' if formato == 'csv' else '.json'
        file_path = filedialog.asksaveasfilename(
            defaultextension=ext,
            filetypes=[("Archivos Forenses", f"*{ext}")],
            title=f"Exportar Auditoría ({formato.upper()})"
        )
        root.destroy()

        if not file_path:
            return json.dumps({'exito': False, 'cancelado': True})

        if formato == 'json':
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(estado_global['analisis'], f, indent=4, ensure_ascii=False)
        else:
            # Exportación CSV básica (IPs atacantes)
            import csv
            ips = estado_global['analisis'].get('top_ips', [])
            keys = ips[0].keys() if ips else []
            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                dict_writer = csv.DictWriter(f, fieldnames=keys)
                dict_writer.writeheader()
                dict_writer.writerows(ips)

        return json.dumps({'exito': True, 'path': file_path})
    except Exception as e:
        return json.dumps({'exito': False, 'error': str(e)})


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

    def encontrar_puerto_libre(puerto_inicial):
        """Busca el primer puerto disponible a partir del inicial."""
        import socket
        puerto = puerto_inicial
        while puerto < puerto_inicial + 10:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if s.connect_ex(('localhost', puerto)) != 0:
                    return puerto
                puerto += 1
        return puerto_inicial

    # Determinar IP local para acceso externo
    def obtener_ip_local():
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "localhost"

    puerto_vortex = encontrar_puerto_libre(8147)
    ip_local = obtener_ip_local()

    print("[+] Iniciando interfaz web...")
    print(f"[+] Acceso LOCAL: http://localhost:{puerto_vortex}")
    print(f"[+] Acceso RED:   http://{ip_local}:{puerto_vortex}")
    print("[+] Se abrirá el navegador automáticamente...")
    print("[+] Para cerrar: Ctrl+C o usa stop.bat")
    print()

    # Opciones comunes de inicio
    opciones_eel = {
        'size': (1400, 900),
        'port': puerto_vortex,
        'host': ip_local, # Usar la IP real detectada para permitir acceso externo y evitar ERR_ADDRESS_INVALID
        'cmdline_args': ['--disable-features=TranslateUI']
    }

    try:
        eel.start('index.html', mode='chrome', **opciones_eel)
    except EnvironmentError:
        try:
            eel.start('index.html', mode='edge', **opciones_eel)
        except Exception:
            eel.start('index.html', mode='default', **opciones_eel)


if __name__ == '__main__':
    main()
