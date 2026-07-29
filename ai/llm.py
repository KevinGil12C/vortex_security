"""
VORTEX Security Intelligence - IA Local (LLM)
Genera reportes de inteligencia y responde preguntas usando modelos locales.
Modelo principal: Qwen/Qwen2.5-1.5B-Instruct
Fallback: TinyLlama
"""

import os
import json


# Ruta absoluta al archivo de contexto
_CONTEXT_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ai-log-analysis-context.md')

# Cache del contexto
_contexto_cache = None

# Cargar config para parámetros de generación
_CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'vortex_config.json')
_config_params = {}
try:
    with open(_CONFIG_PATH, 'r', encoding='utf-8') as f:
        _config_params = json.load(f)
except Exception:
    pass

def _cargar_contexto():
    global _contexto_cache
    if _contexto_cache is not None:
        return _contexto_cache
    try:
        with open(_CONTEXT_PATH, 'r', encoding='utf-8') as f:
            _contexto_cache = f.read()
        print(f"[VORTEX IA] Contexto cargado ({len(_contexto_cache)} caracteres)")
    except Exception as e:
        print(f"[VORTEX IA] No se pudo cargar contexto: {e}")
        _contexto_cache = ""
    return _contexto_cache


class VortexIA:
    """Motor de IA local para generación de reportes y chat."""

    def __init__(self, modelo_nombre=None):
        self.modelo_nombre = modelo_nombre or os.getenv('MODEL_NAME', 'Qwen/Qwen2.5-1.5B-Instruct')
        self.modelo = None
        self.tokenizer = None
        self.disponible = False
        self.error_msg = ""

    def cargar_modelo(self):
        """Carga el modelo de IA local."""
        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer
            import torch

            print(f"[VORTEX IA] Cargando modelo: {self.modelo_nombre}...")

            try:
                self.tokenizer = AutoTokenizer.from_pretrained(
                    self.modelo_nombre,
                    trust_remote_code=True
                )
                self.modelo = AutoModelForCausalLM.from_pretrained(
                    self.modelo_nombre,
                    trust_remote_code=True,
                    dtype=torch.float32,
                    device_map="cpu"
                )
                self.disponible = True
                print(f"[VORTEX IA] Modelo {self.modelo_nombre} cargado exitosamente")
                return True
            except Exception as e:
                print(f"[VORTEX IA] Error con modelo principal: {e}")

                fallback = _config_params.get('fallback', "TinyLlama/TinyLlama-1.1B-Chat-v1.0")
                print(f"[VORTEX IA] Intentando fallback: {fallback}...")
                try:
                    self.tokenizer = AutoTokenizer.from_pretrained(fallback)
                    self.modelo = AutoModelForCausalLM.from_pretrained(
                        fallback,
                        dtype=torch.float32,
                        device_map="cpu"
                    )
                    self.modelo_nombre = fallback
                    self.disponible = True
                    print(f"[VORTEX IA] Modelo fallback cargado: {fallback}")
                    return True
                except Exception as e2:
                    self.error_msg = f"No se pudo cargar ningún modelo: {e2}"
                    print(f"[VORTEX IA] {self.error_msg}")
                    return False

        except ImportError:
            self.error_msg = "transformers no está instalado"
            print(f"[VORTEX IA] {self.error_msg}")
            return False

    def generar_texto(self, prompt, max_tokens=600, chat_mode=False):
        """Genera texto con el modelo cargado."""
        if not self.disponible or not self.modelo:
            print("[VORTEX IA] Error: Modelo no disponible para generar texto")
            return None

        if chat_mode:
            temperatura = _config_params.get('temperatura_chat', _config_params.get('temperatura', 0.5))
        else:
            temperatura = _config_params.get('temperatura', 0.2)
        top_p = _config_params.get('top_p', 0.8)
        rep_penal = _config_params.get('repeticion_penalidad', 1.2)
        if max_tokens is None:
            max_tokens = _config_params.get('max_tokens', 800)

        try:
            import torch
            self.modelo.eval()

            inputs = self.tokenizer(prompt, return_tensors="pt", truncation=True, max_length=1024)
            device = next(self.modelo.parameters()).device
            inputs = {k: v.to(device) for k, v in inputs.items()}

            if self.tokenizer.pad_token_id is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token

            print(f"[VORTEX IA] Generando respuesta (máx {max_tokens} tokens, temp={temperatura})...")

            with torch.no_grad():
                outputs = self.modelo.generate(
                    **inputs,
                    max_new_tokens=max_tokens,
                    temperature=temperatura,
                    top_p=top_p,
                    do_sample=True,
                    repetition_penalty=rep_penal,
                    pad_token_id=self.tokenizer.pad_token_id or self.tokenizer.eos_token_id
                )

            respuesta_bruta = self.tokenizer.decode(outputs[0], skip_special_tokens=False)
            respuesta_bruta = respuesta_bruta.replace('<|im_start|>assistant', '||ASSISTANT||')
            respuesta_bruta = respuesta_bruta.replace('<|im_start|>', '')
            respuesta_bruta = respuesta_bruta.replace('<|im_end|>', '').replace('<|end|>', '').replace('</s>', '')
            respuesta_bruta = respuesta_bruta.replace('<|system|>', '').replace('<|user|>', '')
            respuesta_bruta = respuesta_bruta.replace('<|assistant|>', '')

            if '||ASSISTANT||' in respuesta_bruta:
                respuesta = respuesta_bruta.split('||ASSISTANT||')[-1].strip()
            elif respuesta_bruta.strip().startswith(prompt.strip()[:100]):
                respuesta = respuesta_bruta.replace(prompt, '', 1).strip()
            else:
                respuesta = respuesta_bruta.strip()

            if len(respuesta) < 20:
                print(f"[VORTEX IA] Alerta: Texto generado demasiado corto ({len(respuesta)} chars)")
                return None

            if respuesta.lower().startswith('system') or respuesta.lower().startswith('user'):
                print(f"[VORTEX IA] Eco detectado (response starts with role tag), usando reglas")
                return None

            return respuesta

        except Exception as e:
            print(f"[VORTEX IA] ERROR: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

    def generar_chat(self, mensaje_usuario, datos_analisis=None):
        """
        Genera una respuesta de chat contextual usando la IA local.
        Usa ai-log-analysis-context.md como system prompt para dar contexto táctico.
        Si el modelo no está disponible, devuelve None para que el frontend use fallback.
        """
        if not self.disponible or not self.modelo:
            return None

        contexto = _cargar_contexto()

        resumen = (datos_analisis or {}).get('resumen', {})
        amenazas = (datos_analisis or {}).get('amenazas', [])[:10]
        top_ips = (datos_analisis or {}).get('top_ips', [])[:10]
        anomalias = (datos_analisis or {}).get('anomalias', {})

        datos_str = ""
        if datos_analisis:
            datos_str = f"""
DATOS ACTUALES DEL ANÁLISIS:
- Total logs procesados: {resumen.get('total_logs', 0)}
- Total amenazas: {resumen.get('total_amenazas', 0)}
- Nivel de riesgo: {resumen.get('nivel_riesgo', 'N/A')} (Score: {resumen.get('score_riesgo', 0)}/100)
- IPs únicas: {resumen.get('ips_unicas', 0)}
- IPs baneadas: {resumen.get('ips_baneadas', 0)}
- Anomalías IA: {anomalias.get('total_anomalias', 0)}

AMENAZAS RECIENTES:
{chr(10).join(f"- {a.get('tipo', 'N/A')} desde {a.get('ip', 'N/A')} (Score: {a.get('score', 0)}, Severidad: {a.get('severidad', 'N/A')})" for a in amenazas[:8])}

TOP IPs:
{chr(10).join(f"- {ip.get('ip', 'N/A')}: {ip.get('count', 0)} solicitudes, Score: {ip.get('score', 0)}" for ip in top_ips[:8])}
"""

        context_resumido = contexto[:1500] + "\n\n[CONTEXTO TRUNCADO - usar datos provistos]" if len(contexto) > 1500 else contexto

        system_prompt = f"""Eres VORTEX, un asistente táctico de ciberseguridad. Hablas español con tono militar y directo.

CONTEXTO (resumido):
{context_resumido}

REGLAS:
1. Responde SOLO con los DATOS ACTUALES DEL ANÁLISIS provistos abajo.
2. Si no hay datos, indícalo y sugiere cargar logs.
3. NO inventes datos, IPs, ni números.
4. Sé conciso (máx 4 líneas) y ve directo al punto.
5. Si preguntan por PDF/reporte, di que usen los botones del panel."""
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"{datos_str}\n\n---\n\nMENSAJE DEL OPERADOR: {mensaje_usuario}"}
        ]

        try:
            prompt = self.tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True
            )
        except Exception:
            es_tinyllama = 'tinyllama' in self.modelo_nombre.lower()
            if es_tinyllama:
                prompt = f"<|system|>\n{system_prompt}<|user|>\n{mensaje_usuario}<|assistant|>\n"
            else:
                prompt = f"<|im_start|>system\n{system_prompt}<|im_end|>\n<|im_start|>user\n{mensaje_usuario}<|im_end|>\n<|im_start|>assistant\n"

        max_tokens_val = _config_params.get('max_tokens_chat', _config_params.get('max_tokens', 200))
        respuesta = self.generar_texto(prompt, max_tokens=max_tokens_val, chat_mode=True)
        return respuesta

    def generar_reporte_ia(self, analisis, force_rules=False):
        """
        Genera un reporte de inteligencia basado en el análisis.
        Si el modelo no está disponible o se fuerza reglas, genera un reporte basado en reglas.
        """
        resumen = analisis.get('resumen', {})
        amenazas = analisis.get('amenazas', [])[:10]
        top_ips = analisis.get('top_ips', [])[:5]
        tipos_ataque = analisis.get('tipos_ataque', [])[:8]
        anomalias = analisis.get('anomalias', {})

        if self.disponible and not force_rules:
            return self._generar_con_llm(resumen, amenazas, top_ips, tipos_ataque)
        else:
            return self._generar_con_reglas(resumen, amenazas, top_ips, tipos_ataque, anomalias)

    def _generar_con_llm(self, resumen, amenazas, top_ips, tipos):
        """Genera reporte usando el LLM."""
        # Pre-calcular algunos datos para el prompt (ayuda a la IA a no inventar)
        total_logs = resumen.get('total_logs', 1) 
        total_amenazas = resumen.get('total_amenazas', 0)
        
        tipos_stats = ""
        for t in tipos[:3]:
            porcentaje = (t.get('count', 0) / total_logs) * 100
            tipos_stats += f"- {t.get('tipo', 'N/A')}: {t.get('count', 0)} incidencias ({porcentaje:.1f}% del total)\n"
            
        ip_mas_activa = top_ips[0].get('ip', 'N/A') if top_ips else 'N/A'
        
        prompt = self._construir_prompt(resumen, amenazas, top_ips, tipos, tipos_stats, ip_mas_activa)
        max_tok = _config_params.get('max_tokens_reporte', _config_params.get('max_tokens', 600))
        respuesta = self.generar_texto(prompt, max_tokens=max_tok)

        if respuesta:
            return {
                'informe_ejecutivo': respuesta,
                'generado_por': f'IA Local ({self.modelo_nombre})',
                'disponible': True
            }
        else:
            return self._generar_con_reglas(resumen, amenazas, top_ips, tipos, {})

    def _construir_prompt(self, resumen, amenazas, top_ips, tipos, tipos_stats, ip_mas_activa):
        """Construye el prompt en formato adecuado para el modelo."""
        amenazas_texto = ""
        for a in amenazas[:5]:
            amenazas_texto += f"- {a.get('tipo', 'N/A')} desde {a.get('ip', 'N/A')} (Score: {a.get('score', 0)}, URI: {a.get('uri', 'N/A')})\n"

        ips_texto = ""
        for ip in top_ips[:5]:
            ips_texto += f"- {ip.get('ip', 'N/A')}: {ip.get('count', 0)} solicitudes (Severidad: {ip.get('severidad', 'N/A')})\n"

        es_tinyllama = 'tinyllama' in self.modelo_nombre.lower()
        if es_tinyllama:
            prompt = f"""<|system|>
Eres VORTEX AI, un analista de ciberseguridad militar de élite.
TU MISIÓN: Generar un informe ANALÍTICO, COMPLETO y NUMÉRICO.
REGLAS CRÍTICAS:
1. Habla siempre en ESPAÑOL profesional y técnico.
2. INCLUYE SIEMPRE DATOS NUMÉRICOS, CANTIDADES Y PORCENTAJES.
3. El informe debe ser exhaustivo y sonar como un reporte de inteligencia real.
4. No saludes. No des las gracias. Ve directo a los datos.
5. Firma al final como: "[ PROCESADO POR NÚCLEO NEURAL VORTEX v1.0 ]"
<|user|>
Analiza los datos de rastro de seguridad y genera un reporte detallado:

[MÉTRICAS GLOBALES]
- Volumen Procesado: {resumen.get('total_logs', 0)} registros.
- Amenazas Reales: {resumen.get('total_amenazas', 0)} ráfagas detectadas.
- Riesgo Dashboard: {resumen.get('score_riesgo', 0)}/100 (Nivel: {resumen.get('nivel_riesgo', 'N/A')})
- Exposición de Red: {resumen.get('ips_unicas', 0)} origenes detectados.

[DISTRIBUCIÓN DE CIBER-ATAQUES]
{tipos_stats}
IP más agresiva detectada: {ip_mas_activa}

[DETECCIONES CRÍTICAS]
{amenazas_texto}

[VECTORES DE AMENAZA]
{ips_texto}

Escribe el informe siguiendo estrictamente este formato:
1. RESUMEN TÁCTICO: (Descripción narrativa con cifras clave).
2. DETALLE ANALÍTICO: (Desglose de porcentajes y análisis del actor más peligroso).
3. EVALUACIÓN DE RIESGO: (Resumen de impacto según el score de {resumen.get('score_riesgo', 0)}).
4. RECOMENDACIONES TÁCTICAS: (Mínimo 5 acciones técnicas basadas en los números anteriores).
<|assistant|>
"""
        else:
            prompt = f"""<|im_start|>system
Eres VORTEX AI, un analista de ciberseguridad militar de élite.
TU MISIÓN: Generar un informe ANALÍTICO, COMPLETO y NUMÉRICO.
REGLAS CRÍTICAS:
1. Habla siempre en ESPAÑOL profesional y técnico.
2. INCLUYE SIEMPRE DATOS NUMÉRICOS, CANTIDADES Y PORCENTAJES.
3. El informe debe ser exhaustivo y sonar como un reporte de inteligencia real.
4. No saludes. No des las gracias. Ve directo a los datos.
5. Firma al final como: "[ PROCESADO POR NÚCLEO NEURAL VORTEX v1.0 ]"<|im_end|>
<|im_start|>user
Analiza los datos de rastro de seguridad y genera un reporte detallado:

[MÉTRICAS GLOBALES]
- Volumen Procesado: {resumen.get('total_logs', 0)} registros.
- Amenazas Reales: {resumen.get('total_amenazas', 0)} ráfagas detectadas.
- Riesgo Dashboard: {resumen.get('score_riesgo', 0)}/100 (Nivel: {resumen.get('nivel_riesgo', 'N/A')})
- Exposición de Red: {resumen.get('ips_unicas', 0)} origenes detectados.

[DISTRIBUCIÓN DE CIBER-ATAQUES]
{tipos_stats}
IP más agresiva detectada: {ip_mas_activa}

[DETECCIONES CRÍTICAS]
{amenazas_texto}

[VECTORES DE AMENAZA]
{ips_texto}

Escribe el informe siguiendo estrictamente este formato:
1. RESUMEN TÁCTICO: (Descripción narrativa con cifras clave).
2. DETALLE ANALÍTICO: (Desglose de porcentajes y análisis del actor más peligroso).
3. EVALUACIÓN DE RIESGO: (Resumen de impacto según el score de {resumen.get('score_riesgo', 0)}).
4. RECOMENDACIONES TÁCTICAS: (Mínimo 5 acciones técnicas basadas en los números anteriores).<|im_end|>
<|im_start|>assistant
"""
        return prompt

    def _generar_con_reglas(self, resumen, amenazas, top_ips, tipos, anomalias):
        """Genera reporte basado en reglas cuando no hay LLM disponible."""
        total = resumen.get('total_logs', 0)
        total_amenazas = resumen.get('total_amenazas', 0)
        score = resumen.get('score_riesgo', 0)
        nivel = resumen.get('nivel_riesgo', 'BAJO')
        ips_unicas = resumen.get('ips_unicas', 0)
        ips_baneadas = resumen.get('ips_baneadas', 0)

        # Informe ejecutivo
        informe = f"""═══════════════════════════════════════════════════════
  VORTEX SECURITY INTELLIGENCE - INFORME EJECUTIVO
═══════════════════════════════════════════════════════

<span class="mat-icon mat-icon-sm" style="vertical-align:middle;">bar_chart</span> RESUMEN TÁCTICO:
Se analizaron {total} registros de seguridad procedentes de {ips_unicas} direcciones IP únicas.
Se identificaron {total_amenazas} eventos de amenaza que requieren atención.
{'Se banearon ' + str(ips_baneadas) + ' direcciones IP por actividad maliciosa.' if ips_baneadas else ''}

<span class="mat-icon mat-icon-sm" style="vertical-align:middle;">gps_fixed</span> EVALUACIÓN DE RIESGO:
Nivel de riesgo general: {nivel}
Puntuación de riesgo: {score}/100
"""

        if score >= 70:
            informe += """
<span class="mat-icon mat-icon-sm" style="vertical-align:middle;color:var(--red-alert);">warning</span> ESTADO: CRÍTICO
El sistema está bajo ataque activo. Se recomienda acción inmediata.
"""
        elif score >= 40:
            informe += """
<span class="mat-icon mat-icon-sm" style="vertical-align:middle;color:var(--yellow-warn);">warning</span> ESTADO: ELEVADO
Se detectó actividad sospechosa significativa. Se recomienda monitoreo intensificado.
"""
        else:
            informe += """
<span class="mat-icon mat-icon-sm" style="vertical-align:middle;color:var(--green-neon);">check_circle</span> ESTADO: NORMAL
La actividad detectada está dentro de parámetros normales con alertas menores.
"""

        # Amenazas principales
        if amenazas:
            informe += '\n<span class="mat-icon mat-icon-sm" style="vertical-align:middle;">warning</span> AMENAZAS PRINCIPALES:\n'
            for i, a in enumerate(amenazas[:5], 1):
                informe += f"  {i}. {a.get('tipo', 'N/A')} - IP: {a.get('ip', 'N/A')} (Score: {a.get('score', 0)})\n"
                informe += f"     URI: {a.get('uri', 'N/A')}\n"

        # Top atacantes
        if top_ips:
            informe += '\n<span class="mat-icon mat-icon-sm" style="vertical-align:middle;">trackpad</span> ATACANTES PRINCIPALES:\n'
            for ip in top_ips[:5]:
                estado = '<span class="mat-icon mat-icon-sm" style="vertical-align:middle;color:var(--red-alert);">block</span> BANEADA' if ip.get('baneada') else '<span class="mat-icon mat-icon-sm" style="vertical-align:middle;color:var(--yellow-warn);">radar</span> ACTIVA'
                informe += f"  • {ip.get('ip', 'N/A')} [{estado}] - {ip.get('count', 0)} peticiones - Score: {ip.get('score', 0)}\n"

        # Tipos de ataque
        if tipos:
            informe += '\n<span class="mat-icon mat-icon-sm" style="vertical-align:middle;">list_alt</span> TIPOS DE ATAQUE DETECTADOS:\n'
            for t in tipos:
                informe += f"  • {t.get('tipo', 'N/A')}: {t.get('count', 0)} incidencias\n"

        informe += '\n<span class="mat-icon mat-icon-sm" style="vertical-align:middle;">shield</span> RECOMENDACIONES DE SEGURIDAD:\n'
        recomendaciones = self._generar_recomendaciones(amenazas, tipos, score)
        for i, rec in enumerate(recomendaciones, 1):
            informe += f"  {i}. {rec}\n"

        informe += f"""
═══════════════════════════════════════════════════════
  Generado por VORTEX Security Intelligence
  [ MOTOR ANALÍTICO ESTÁTICO - BASADO EN REGLAS ]
═══════════════════════════════════════════════════════"""

        return {
            'informe_ejecutivo': informe,
            'generado_por': 'Motor de Reglas VORTEX',
            'disponible': True,
            'recomendaciones': recomendaciones
        }

    def _generar_recomendaciones(self, amenazas, tipos, score):
        """Genera recomendaciones de seguridad basadas en el análisis."""
        recs = []
        tipos_nombres = [t.get('tipo', '') for t in tipos]

        if 'SQL Injection' in tipos_nombres:
            recs.append("Implementar prepared statements y validación de entrada en todos los endpoints.")
            recs.append("Revisar configuración del WAF para reglas de SQL Injection.")

        if 'XSS' in tipos_nombres:
            recs.append("Implementar Content Security Policy (CSP) y sanitización de output.")
            recs.append("Activar HttpOnly y Secure flags en todas las cookies.")

        if 'Directory Traversal' in tipos_nombres:
            recs.append("Restringir acceso a directorios sensibles y validar paths de entrada.")

        if 'Bot Malicioso' in tipos_nombres:
            recs.append("Implementar rate limiting y CAPTCHA para endpoints sensibles.")
            recs.append("Bloquear User-Agents de herramientas de escaneo conocidas.")

        if 'Fuerza Bruta' in tipos_nombres:
            recs.append("Implementar bloqueo temporal de cuenta tras intentos fallidos.")
            recs.append("Considerar autenticación multi-factor (MFA).")

        if 'Reconocimiento' in tipos_nombres:
            recs.append("Remover archivos sensibles (.env, .git) del servidor público.")
            recs.append("Implementar honeypots para detectar actividad de reconocimiento.")

        if score >= 70:
            recs.append("URGENTE: Considerar activar modo de defensa reforzada.")
            recs.append("Notificar al equipo de respuesta a incidentes (CSIRT).")

        if not recs:
            recs.append("Mantener monitoreo continuo de logs de seguridad.")
            recs.append("Actualizar reglas de detección periódicamente.")
            recs.append("Realizar auditorías de seguridad de forma regular.")

        return recs


# Instancia global
_ia_instance = None


def obtener_ia(modelo_nombre=None):
    """Obtiene o crea la instancia global de IA."""
    global _ia_instance
    if _ia_instance is None:
        _ia_instance = VortexIA(modelo_nombre)
    return _ia_instance
