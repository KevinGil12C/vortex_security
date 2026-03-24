"""
VORTEX Security Intelligence - Generador de Reportes PDF
Genera reportes profesionales con branding VORTEX.
"""

import os
import io
from datetime import datetime


def generar_reporte_pdf(analisis, ruta_salida=None):
    """
    Genera un reporte PDF profesional con los resultados del análisis.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch, cm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            PageBreak, HRFlowable
        )
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    except ImportError:
        return {'error': 'reportlab no está instalado. Ejecutar: pip install reportlab', 'ruta': ''}

    if not ruta_salida:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        ruta_salida = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'reports', f'VORTEX_Report_{timestamp}.pdf')

    # Crear directorio si no existe
    os.makedirs(os.path.dirname(ruta_salida), exist_ok=True)

    # ═══════════════════════════════════════════════════
    # CONFIGURACIÓN DEL DOCUMENTO
    # ═══════════════════════════════════════════════════

    doc = SimpleDocTemplate(
        ruta_salida,
        pagesize=letter,
        rightMargin=50,
        leftMargin=50,
        topMargin=50,
        bottomMargin=50
    )

    # Colores VORTEX
    VORTEX_DARK = colors.HexColor('#0a0a1a')
    VORTEX_GREEN = colors.HexColor('#00ff9f')
    VORTEX_BLUE = colors.HexColor('#00d4ff')
    VORTEX_RED = colors.HexColor('#ff3366')
    VORTEX_YELLOW = colors.HexColor('#ffaa00')
    VORTEX_GRAY = colors.HexColor('#2a2a3a')
    VORTEX_LIGHT = colors.HexColor('#e0e0e0')

    # Estilos
    styles = getSampleStyleSheet()

    titulo_style = ParagraphStyle(
        'VortexTitulo',
        parent=styles['Title'],
        fontName='Helvetica-Bold',
        fontSize=22,
        textColor=VORTEX_DARK,
        spaceAfter=20,
        alignment=TA_CENTER
    )

    subtitulo_style = ParagraphStyle(
        'VortexSubtitulo',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        textColor=VORTEX_DARK,
        spaceBefore=15,
        spaceAfter=8,
        borderWidth=1,
        borderColor=VORTEX_GREEN,
        borderPadding=5,
    )

    normal_style = ParagraphStyle(
        'VortexNormal',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        textColor=colors.HexColor('#333333'),
        spaceAfter=6,
    )

    alerta_style = ParagraphStyle(
        'VortexAlerta',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        textColor=VORTEX_RED,
        spaceAfter=6,
    )

    # ═══════════════════════════════════════════════════
    # CONSTRUIR CONTENIDO
    # ═══════════════════════════════════════════════════

    elementos = []
    resumen = analisis.get('resumen', {})

    # ── PORTADA ──
    elementos.append(Spacer(1, 80))
    elementos.append(Paragraph("◆ VORTEX SECURITY INTELLIGENCE ◆", titulo_style))
    elementos.append(Paragraph("Tactical Analysis Core - Reporte de Seguridad", ParagraphStyle(
        'Subtitulo2', parent=styles['Normal'], fontSize=13, alignment=TA_CENTER,
        textColor=colors.HexColor('#555555'), spaceAfter=30
    )))

    # Línea divisora
    elementos.append(HRFlowable(width="80%", thickness=2, color=VORTEX_GREEN, spaceAfter=20))

    # Fecha
    fecha = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
    elementos.append(Paragraph(f"Fecha de generación: {fecha}", ParagraphStyle(
        'Fecha', parent=styles['Normal'], fontSize=10, alignment=TA_CENTER,
        textColor=colors.HexColor('#777777'), spaceAfter=40
    )))

    # Métricas rápidas
    nivel = resumen.get('nivel_riesgo', 'BAJO')
    score = resumen.get('score_riesgo', 0)
    color_nivel = VORTEX_RED if nivel == 'ALTO' else VORTEX_YELLOW if nivel == 'MEDIO' else VORTEX_GREEN

    metricas_data = [
        ['MÉTRICA', 'VALOR'],
        ['Total de Logs Analizados', str(resumen.get('total_logs', 0))],
        ['Amenazas Detectadas', str(resumen.get('total_amenazas', 0))],
        ['Score de Riesgo', f'{score}/100'],
        ['Nivel de Riesgo', nivel],
        ['IPs Únicas', str(resumen.get('ips_unicas', 0))],
        ['IPs Baneadas', str(resumen.get('ips_baneadas', 0))],
    ]

    tabla_metricas = Table(metricas_data, colWidths=[250, 200])
    tabla_metricas.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), VORTEX_DARK),
        ('TEXTCOLOR', (0, 0), (-1, 0), VORTEX_GREEN),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f5f5f5')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f0f0')]),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    elementos.append(tabla_metricas)
    elementos.append(Spacer(1, 20))

    elementos.append(PageBreak())

    # ── TOP IPS ──
    elementos.append(Paragraph("🎯 TOP DIRECCIONES IP AMENAZANTES", subtitulo_style))
    top_ips = analisis.get('top_ips', [])

    if top_ips:
        ip_data = [['IP', 'Peticiones', 'Score', 'Severidad', 'Estado']]
        for ip_info in top_ips[:15]:
            estado = '🔴 BANEADA' if ip_info.get('baneada') else '🟢 ACTIVA'
            ip_data.append([
                ip_info.get('ip', 'N/A'),
                str(ip_info.get('count', 0)),
                str(ip_info.get('score', 0)),
                ip_info.get('severidad', 'INFO'),
                estado
            ])

        tabla_ips = Table(ip_data, colWidths=[100, 70, 60, 80, 100])
        tabla_ips.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), VORTEX_DARK),
            ('TEXTCOLOR', (0, 0), (-1, 0), VORTEX_GREEN),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f0f0')]),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        elementos.append(tabla_ips)
    else:
        elementos.append(Paragraph("No se detectaron IPs amenazantes.", normal_style))

    elementos.append(Spacer(1, 20))

    # ── TOP URIS ──
    elementos.append(Paragraph("🔗 TOP URIs ATACADAS", subtitulo_style))
    top_uris = analisis.get('top_uris', [])

    if top_uris:
        uri_data = [['URI', 'Peticiones']]
        for uri_info in top_uris[:15]:
            uri_texto = uri_info.get('uri', 'N/A')
            if len(uri_texto) > 60:
                uri_texto = uri_texto[:57] + '...'
            uri_data.append([uri_texto, str(uri_info.get('count', 0))])

        tabla_uris = Table(uri_data, colWidths=[350, 80])
        tabla_uris.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), VORTEX_DARK),
            ('TEXTCOLOR', (0, 0), (-1, 0), VORTEX_GREEN),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f0f0')]),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        elementos.append(tabla_uris)
    else:
        elementos.append(Paragraph("No se detectaron URIs atacadas.", normal_style))

    elementos.append(Spacer(1, 20))

    # ── TIPOS DE ATAQUE ──
    elementos.append(Paragraph("🚨 TIPOS DE ATAQUES DETECTADOS", subtitulo_style))
    tipos_ataque = analisis.get('tipos_ataque', [])

    if tipos_ataque:
        tipos_data = [['Tipo de Ataque', 'Incidencias']]
        for tipo in tipos_ataque:
            tipos_data.append([tipo.get('tipo', 'N/A'), str(tipo.get('count', 0))])

        tabla_tipos = Table(tipos_data, colWidths=[300, 100])
        tabla_tipos.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), VORTEX_DARK),
            ('TEXTCOLOR', (0, 0), (-1, 0), VORTEX_GREEN),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f0f0')]),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        elementos.append(tabla_tipos)

    elementos.append(PageBreak())

    # ── INFORME IA ──
    informe_ia = analisis.get('informe_ia', {})
    if informe_ia and informe_ia.get('informe_ejecutivo'):
        elementos.append(Paragraph("🤖 ANÁLISIS DE INTELIGENCIA ARTIFICIAL", subtitulo_style))
        # Dividir informe en párrafos
        texto_informe = informe_ia['informe_ejecutivo']
        for linea in texto_informe.split('\n'):
            linea = linea.strip()
            if linea:
                # Escapar caracteres especiales para XML
                linea = linea.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                if linea.startswith('═') or linea.startswith('─'):
                    elementos.append(HRFlowable(width="100%", thickness=1, color=VORTEX_GREEN))
                elif linea.startswith('⚠') or linea.startswith('🚨') or linea.startswith('⚡'):
                    elementos.append(Paragraph(linea, alerta_style))
                else:
                    elementos.append(Paragraph(linea, normal_style))
        elementos.append(Spacer(1, 20))

    # ── PIE DE PÁGINA / BRANDING ──
    elementos.append(Spacer(1, 30))
    elementos.append(HRFlowable(width="100%", thickness=2, color=VORTEX_GREEN))
    elementos.append(Spacer(1, 10))
    elementos.append(Paragraph(
        "VORTEX Security Intelligence - Tactical Analysis Core",
        ParagraphStyle('Footer', parent=styles['Normal'], fontSize=9,
                       alignment=TA_CENTER, textColor=colors.HexColor('#999999'))
    ))
    elementos.append(Paragraph(
        "Este reporte es confidencial y de uso exclusivo del equipo de seguridad.",
        ParagraphStyle('Footer2', parent=styles['Normal'], fontSize=8,
                       alignment=TA_CENTER, textColor=colors.HexColor('#bbbbbb'))
    ))

    # ═══════════════════════════════════════════════════
    # GENERAR PDF
    # ═══════════════════════════════════════════════════

    try:
        doc.build(elementos)
        return {
            'ruta': ruta_salida,
            'nombre': os.path.basename(ruta_salida),
            'exito': True,
            'mensaje': f'Reporte generado exitosamente: {os.path.basename(ruta_salida)}'
        }
    except Exception as e:
        return {
            'error': f'Error al generar PDF: {str(e)}',
            'ruta': '',
            'exito': False
        }
