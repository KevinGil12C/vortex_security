"""
VORTEX Security Intelligence - Generador de Reportes PDF
Genera reportes profesionales con branding VORTEX.
"""

import os
import io
from datetime import datetime


def generar_reporte_pdf(analisis, ruta_salida=None, mapa_b64=None, graficos_b64=None):
    """Genera una Auditoría Maestra VORTEX (Versión Printable/Blanca)."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            PageBreak, HRFlowable, Image
        )
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        from reportlab.graphics.shapes import Drawing, Rect
        from reportlab.graphics.charts.barcharts import VerticalBarChart
        from reportlab.graphics.charts.piecharts import Pie
        from reportlab.graphics.charts.textlabels import Label
        import base64
    except ImportError:
        return {'error': 'reportlab no está instalado.', 'ruta': ''}

    if not ruta_salida:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        ruta_salida = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'reports', f'VORTEX_Audit_Printable_{timestamp}.pdf')

    os.makedirs(os.path.dirname(ruta_salida), exist_ok=True)
    logo_path = os.path.join(os.path.dirname(__file__), 'vortex_logo.png')
    map_path = os.path.join(os.path.dirname(__file__), 'vortex_map.png')
    
    if mapa_b64:
        try:
            map_data = base64.b64decode(mapa_b64.split(',')[1] if ',' in mapa_b64 else mapa_b64)
            with open(map_path, 'wb') as f:
                f.write(map_data)
        except Exception as e:
            pass

    # Paleta Cyberpunk (Printable)
    VORTEX_BG = colors.white
    VORTEX_BLUE = colors.HexColor('#0088cc')  
    VORTEX_GREEN = colors.HexColor('#00aa88') 
    VORTEX_RED = colors.HexColor('#cc0033')   
    VORTEX_TEXT = colors.black
    VORTEX_DARK = colors.HexColor('#0a0a1a')

    doc = SimpleDocTemplate(ruta_salida, pagesize=letter, rightMargin=35, leftMargin=35, topMargin=0.7*inch, bottomMargin=0.5*inch)

    def draw_dark_theme(canvas, doc):
        canvas.saveState()
        # Branding Header
        if os.path.exists(logo_path):
            canvas.drawImage(logo_path, 35, 742, width=32, height=32, mask='auto', preserveAspectRatio=True)
        canvas.setStrokeColor(VORTEX_BLUE); canvas.setLineWidth(2)
        canvas.line(35, 735, 575, 735)
        
        canvas.setFont('Helvetica-Bold', 11); canvas.setFillColor(VORTEX_DARK)
        canvas.drawString(75, 755, "VORTEX SECURITY - TACTICAL COMMAND REPORT")
        canvas.setFont('Helvetica', 7); canvas.setFillColor(colors.grey)
        canvas.drawString(75, 742, f"AUDITORÍA LVL 5 | {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        
        # Footer
        canvas.setFont('Helvetica', 7); canvas.setFillColor(colors.grey)
        canvas.drawString(35, 25, "PROCESADO POR VORTEX NEURAL | IMPRESIÓN FORENSE")
        canvas.drawRightString(575, 25, f"PÁGINA {doc.page} | ENLACE ENCRIPTADO")
        canvas.restoreState()

    styles = getSampleStyleSheet()
    title_st = ParagraphStyle('T', fontSize=22, textColor=VORTEX_DARK, alignment=TA_CENTER, fontName='Helvetica-Bold', spaceAfter=15)
    num_st = ParagraphStyle('N', fontSize=18, alignment=TA_CENTER, fontName='Helvetica-Bold', spaceBefore=0, spaceAfter=0)
    sect_st = ParagraphStyle('H', fontSize=10, textColor=colors.white, backColor=VORTEX_DARK, borderPadding=5, spaceBefore=15, spaceAfter=10, fontName='Helvetica-Bold')
    desc_st = ParagraphStyle('D', fontSize=8, textColor=colors.grey, alignment=TA_LEFT, leading=10, italic=True)
    body_st = ParagraphStyle('B', fontSize=9, textColor=VORTEX_TEXT, leading=12)

    elementos = []
    resumen = analisis.get('resumen', {})

    # ── PÁGINA 1: COMMAND SUMMARY ──
    elementos.append(Spacer(1, 0.4*inch))
    elementos.append(Paragraph("SÍNTESIS TÁCTICA DE OPERACIONES", title_st))
    
    # Grid de Métricas (Estilo Neón)
    m_data = [
        [Paragraph("<b>NODOS ÚNICOS</b>", body_st), Paragraph("<b>AMENAZAS</b>", body_st), Paragraph("<b>NIVEL RIESGO</b>", body_st)],
        [Paragraph(f"<font color='#00d4ff'>{resumen.get('ips_unicas', 0)}</font>", num_st), 
         Paragraph(f"<font color='#00d4ff'>{resumen.get('total_amenazas', 0)}</font>", num_st), 
         Paragraph(f"<font color='#ff3366'>{resumen.get('score_riesgo', 0)}/100</font>", num_st)]
    ]
    t_m = Table(m_data, colWidths=[1.8*inch, 1.8*inch, 1.8*inch], rowHeights=[None, 0.4*inch])
    t_m.setStyle(TableStyle([('BOX', (0,0), (-1,-1), 2, VORTEX_GREEN), ('INNERGRID', (0,0), (-1,-1), 0.5, VORTEX_GREEN), ('ALIGN', (0,0), (-1,-1), 'CENTER'), ('VALIGN', (0,0), (-1,-1), 'MIDDLE')]))
    elementos.append(t_m)

    chart_paths = {}
    if graficos_b64:
        for key, b64 in graficos_b64.items():
            if b64:
                try:
                    c_path = os.path.join(os.path.dirname(__file__), f'vortex_chart_{key}.png')
                    c_data = base64.b64decode(b64.split(',')[1] if ',' in b64 else b64)
                    with open(c_path, 'wb') as f:
                        f.write(c_data)
                    chart_paths[key] = c_path
                except Exception:
                    pass

    # Mapa (Immersive)
    if os.path.exists(map_path):
        elementos.append(Paragraph("ESTADO GLOBAL DE AMENAZAS", sect_st))
        elementos.append(Image(map_path, width=5.5*inch, height=3*inch, kind='proportional'))
        elementos.append(Paragraph("<b>MONITOREO GEOGRÁFICO:</b> Los clusters visualizados corresponden a la actividad detectada en tiempo real por los nodos externos de VORTEX.", desc_st))

    # Gráfico 1: Vectores
    tipos = analisis.get('tipos_ataque', [])
    if tipos:
        elementos.append(Paragraph("AUDITORÍA DE VECTORES", sect_st))
        if 'ataques' in chart_paths and os.path.exists(chart_paths['ataques']):
            elementos.append(Image(chart_paths['ataques'], width=5.5*inch, height=2.5*inch, kind='proportional'))
        else:
            elementos.append(Paragraph("<i>[Gráfico de Vectores no disponible]</i>", desc_st))
        elementos.append(Spacer(1, 10))
        elementos.append(Paragraph("<b>VECTORES TÁCTICOS:</b> Distribución de intentos de ataque clasificados por su firma de ejecución. Una mayor concentración en ciertos vectores indica una campaña focalizada.", desc_st))

    elementos.append(PageBreak())

    # ── PÁGINA 2: LÍNEA DE TIEMPO Y SISTEMAS ──
    # Gráfico 2: Timeline
    timeline = analisis.get('timeline', [])
    if timeline:
        elementos.append(Paragraph("HISTORIAL DE ATAQUES (TIMELINE)", sect_st))
        if 'timeline' in chart_paths and os.path.exists(chart_paths['timeline']):
            elementos.append(Image(chart_paths['timeline'], width=5.5*inch, height=2*inch, kind='proportional'))
        else:
            elementos.append(Paragraph("<i>[Timeline no disponible]</i>", desc_st))
        elementos.append(Spacer(1, 10))
        elementos.append(Paragraph("<b>ANÁLISIS TEMPORAL:</b> Frecuencia de incidentes a lo largo del periodo analizado. Útil para detectar patrones rítmicos o ventanas de vulnerabilidad sistemáticas.", desc_st))

    # Gráfico 3: OS y Navegadores (Lado a lado o secuencial)
    os_l = analisis.get('os_data', []); br_l = analisis.get('browsers_data', [])
    if os_l or br_l:
        elementos.append(Paragraph("PERFILADO DEL ADVERSARIO (FINGERPRINTING)", sect_st))
        
        img_os = Image(chart_paths['os'], width=2.5*inch, height=2.5*inch, kind='proportional') if 'os' in chart_paths else Paragraph("N/A", desc_st)
        img_br = Image(chart_paths['browsers'], width=2.5*inch, height=2.5*inch, kind='proportional') if 'browsers' in chart_paths else Paragraph("N/A", desc_st)
        
        t_perfil = Table([[img_os, img_br]], colWidths=[2.75*inch, 2.75*inch])
        t_perfil.setStyle(TableStyle([('ALIGN', (0,0), (-1,-1), 'CENTER'), ('VALIGN', (0,0), (-1,-1), 'MIDDLE')]))
        elementos.append(t_perfil)
        
        elementos.append(Spacer(1, 10))
        elementos.append(Paragraph("<b>PERFILADO TÉCNICO:</b> Identificación de sistemas operativos (Izquierda) y clientes HTTP (Derecha) utilizados en la incursión. Este footprint permite trazar la sofisticación técnica del atacante.", desc_st))

    # Gráfico 4: Perfiles
    perf_l = analisis.get('perfiles_atacantes', [])
    if perf_l:
        elementos.append(Paragraph("CLASIFICACIÓN DE ATACANTES", sect_st))
        p_counts = {}
        from collections import Counter
        p_counts = Counter(p.get('clasificacion', 'Unknown') for p in perf_l)
        perfiles_txt = " • ".join([f"<b>{k}:</b> {v}" for k, v in p_counts.items()])
        elementos.append(Paragraph(f"Distribución de perfiles detectados: {perfiles_txt}", body_st))
        elementos.append(Spacer(1, 10))
        elementos.append(Paragraph("<b>EVALUACIÓN DE AMENAZA:</b> Categorización final generada por el motor de inferencia táctica (Ej. Reconocimiento VS Explotación).", desc_st))

    elementos.append(PageBreak())

    # ── PÁGINA 3: LISTADO DE NODOS ──
    elementos.append(Paragraph("ANÁLISIS DETALLADO DE NODOS CRÍTICOS", sect_st))
    top_ips = analisis.get('top_ips', [])
    if top_ips:
        ip_data = [['ID', 'IP ORIGEN', 'SCORE', 'SEVERIDAD', 'STATUS']]
        for i, ip in enumerate(top_ips[:22], 1):
            ip_data.append([str(i), ip.get('ip'), str(ip.get('score')), ip.get('severidad'), "BANEADO" if ip.get('baneada') else "ACTIVA"])
        t = Table(ip_data, colWidths=[0.5*inch, 2.0*inch, 0.8*inch, 1*inch, 1.2*inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), VORTEX_GREEN), ('TEXTCOLOR', (0,0), (-1,0), VORTEX_BG),
            ('TEXTCOLOR', (0,1), (-1,-1), VORTEX_TEXT), ('GRID', (0,0), (-1,-1), 0.5, VORTEX_GREEN),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'), ('FONTSIZE', (0,0), (-1,-1), 8)
        ]))
        elementos.append(t)

    # Neural / Motor de Reglas
    inf_ia = analisis.get('informe_ia', {})
    if inf_ia.get('informe_ejecutivo'):
        elementos.append(PageBreak())
        elementos.append(Paragraph(f"SÍNTESIS DE INTELIGENCIA: {inf_ia.get('generado_por', 'VORTEX')}", sect_st))
        
        import re
        texto_crudo = inf_ia['informe_ejecutivo']
        
        # Eliminar emojis explícitos y caracteres de caja
        texto_limpio = re.sub(r'[═║╔╗╚╝╠╣╦╩╬│─┌┐└┘├┤┬┴┼✅✔️✖️❌⚠️🛡️🚨ℹ️⚡⭐✨📊📈]', '', texto_crudo)
        texto_limpio = re.sub(r'[\U00010000-\U0010ffff]', '', texto_limpio)
        
        for p in texto_limpio.split('\n'):
            p_str = p.strip()
            if p_str:
                elementos.append(Paragraph(f"<font color='#00d4ff'>›</font> {p_str}", body_st))
                elementos.append(Spacer(1, 4))

    try:
        doc.build(elementos, onFirstPage=draw_dark_theme, onLaterPages=draw_dark_theme)
        return {'ruta': ruta_salida, 'nombre': os.path.basename(ruta_salida), 'exito': True}
    except Exception as e:
        return {'exito': False, 'error': str(e)}
