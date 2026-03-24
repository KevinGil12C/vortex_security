"""
VORTEX Security Intelligence - IA Local (LLM)
Genera reportes de inteligencia usando modelos locales.
Modelo principal: Qwen/Qwen1.5-0.5B-Chat
Fallback: TinyLlama
"""

import os
import json


class VortexIA:
    """Motor de IA local para generación de reportes."""

    def __init__(self, modelo_nombre=None):
        self.modelo_nombre = modelo_nombre or os.getenv('MODEL_NAME', 'Qwen/Qwen1.5-0.5B-Chat')
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

            # Intentar cargar modelo principal
            try:
                self.tokenizer = AutoTokenizer.from_pretrained(
                    self.modelo_nombre,
                    trust_remote_code=True
                )
                self.modelo = AutoModelForCausalLM.from_pretrained(
                    self.modelo_nombre,
                    trust_remote_code=True,
                    torch_dtype=torch.float32,
                    device_map="cpu"
                )
                self.disponible = True
                print(f"[VORTEX IA] Modelo {self.modelo_nombre} cargado exitosamente")
                return True
            except Exception as e:
                print(f"[VORTEX IA] Error con modelo principal: {e}")

                # Fallback a TinyLlama
                fallback = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
                print(f"[VORTEX IA] Intentando fallback: {fallback}...")
                try:
                    self.tokenizer = AutoTokenizer.from_pretrained(fallback)
                    self.modelo = AutoModelForCausalLM.from_pretrained(
                        fallback,
                        torch_dtype=torch.float32,
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

    def generar_texto(self, prompt, max_tokens=600):
        """Genera texto con el modelo cargado."""
        if not self.disponible or not self.modelo:
            print("[VORTEX IA] Error: Modelo no disponible para generar texto")
            return None

        try:
            import torch
            
            # Asegurar que el modelo esté en modo evaluación
            self.modelo.eval()

            # Tokenización
            inputs = self.tokenizer(prompt, return_tensors="pt", truncation=True, max_length=1024)
            
            # Mover a device
            device = next(self.modelo.parameters()).device
            inputs = {k: v.to(device) for k, v in inputs.items()}

            # Configuración de padding si es necesario
            if self.tokenizer.pad_token_id is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token

            print(f"[VORTEX IA] Generando respuesta (máx {max_tokens} tokens)...")

            with torch.no_grad():
                outputs = self.modelo.generate(
                    **inputs,
                    max_new_tokens=max_tokens,
                    temperature=0.8,
                    top_p=0.9,
                    do_sample=True,
                    repetition_penalty=1.1,
                    pad_token_id=self.tokenizer.pad_token_id or self.tokenizer.eos_token_id
                )

            respuesta_bruta = self.tokenizer.decode(outputs[0], skip_special_tokens=True)

            # Limpieza mejorada:
            if "assistant" in respuesta_bruta:
                respuesta = respuesta_bruta.split("assistant")[-1].strip()
            elif "TÁCTICO" in respuesta_bruta:
                # Si no usó etiquetas pero empezó el reporte
                idx = respuesta_bruta.find("TÁCTICO")
                respuesta = respuesta_bruta[idx:].strip()
            else:
                # Fallback final: intentar quitar el prompt si se detecta
                if respuesta_bruta.startswith(prompt[:100]): # Coincidencia parcial
                    respuesta = respuesta_bruta.replace(prompt, "").strip()
                else:
                    respuesta = respuesta_bruta.strip()
            
            # Si después de todo sigue vacío o es muy corto, falló
            if len(respuesta) < 20: 
                print(f"[VORTEX IA] Alerta: Texto generado demasiado corto o vacío ({len(respuesta)} chars)")
                return None

            return respuesta

        except Exception as e:
            print(f"[VORTEX IA] ERROR CRÍTICO durante generación: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

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
        prompt = self._construir_prompt(resumen, amenazas, top_ips, tipos)
        respuesta = self.generar_texto(prompt, max_tokens=600)

        # Debug logs
        if respuesta:
            print(f"[VORTEX IA] Respuesta LLM generada ({len(respuesta)} caracteres)")
            return {
                'informe_ejecutivo': respuesta,
                'generado_por': f'IA Local ({self.modelo_nombre})',
                'disponible': True
            }
        else:
            print("[VORTEX IA] Alerta: El LLM devolvió una respuesta vacía o falló. Usando motor de reglas.")
            return self._generar_con_reglas(resumen, amenazas, top_ips, tipos, {})

    def _construir_prompt(self, resumen, amenazas, top_ips, tipos):
        """Construye el prompt en formato ChatML para mejores resultados."""
        amenazas_texto = ""
        for a in amenazas[:5]:
            amenazas_texto += f"- {a.get('tipo', 'N/A')} desde {a.get('ip', 'N/A')} (score: {a.get('score', 0)})\n"

        ips_texto = ""
        for ip in top_ips[:5]:
            ips_texto += f"- {ip.get('ip', 'N/A')}: {ip.get('count', 0)} peticiones, score: {ip.get('score', 0)}\n"

        # Formato ChatML universal para Qwen/TinyLlama
        prompt = f"""<|im_start|>system
Eres un analista de ciberseguridad experto. Tu tarea es generar informes ejecutivos profesionales, técnicos y detallados en ESPAÑOL. Proporciona recomendaciones tácticas y una evaluación de riesgo clara.<|im_end|>
<|im_start|>user
Genera un informe ejecutivo de seguridad en ESPAÑOL basado en estos datos:

[DATOS DE ANÁLISIS]
- Logs analizados: {resumen.get('total_logs', 0)}
- Amenazas detectadas: {resumen.get('total_amenazas', 0)}
- Nivel de riesgo: {resumen.get('nivel_riesgo', 'N/A')} (Score: {resumen.get('score_riesgo', 0)}/100)
- IPs únicas: {resumen.get('ips_unicas', 0)}
- IPs baneadas: {resumen.get('ips_baneadas', 0)}

[AMENAZAS PRINCIPALES]
{amenazas_texto}

[ATACANTES TOP]
{ips_texto}

Escribe el informe con las secciones: "RESUMEN TÁCTICO", "EVALUACIÓN DE RIESGO" y "RECOMENDACIONES". Debe ser un tono serio y profesional. 
IMPORTANTE: No menciones que eres un motor de reglas. Al final del informe escribe SIEMPRE esta firma: "[ PROCESADO POR NÚCLEO NEURAL VORTEX v1.0 ]"<|im_end|>
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

📊 RESUMEN TÁCTICO:
Se analizaron {total} registros de seguridad procedentes de {ips_unicas} direcciones IP únicas.
Se identificaron {total_amenazas} eventos de amenaza que requieren atención.
{'Se banearon ' + str(ips_baneadas) + ' direcciones IP por actividad maliciosa.' if ips_baneadas else ''}

🎯 EVALUACIÓN DE RIESGO:
Nivel de riesgo general: {nivel}
Puntuación de riesgo: {score}/100
"""

        if score >= 70:
            informe += """
⚠️ ESTADO: CRÍTICO
El sistema está bajo ataque activo. Se recomienda acción inmediata.
"""
        elif score >= 40:
            informe += """
⚠️ ESTADO: ELEVADO
Se detectó actividad sospechosa significativa. Se recomienda monitoreo intensificado.
"""
        else:
            informe += """
✅ ESTADO: NORMAL
La actividad detectada está dentro de parámetros normales con alertas menores.
"""

        # Amenazas principales
        if amenazas:
            informe += "\n🚨 AMENAZAS PRINCIPALES:\n"
            for i, a in enumerate(amenazas[:5], 1):
                informe += f"  {i}. {a.get('tipo', 'N/A')} - IP: {a.get('ip', 'N/A')} (Score: {a.get('score', 0)})\n"
                informe += f"     URI: {a.get('uri', 'N/A')}\n"

        # Top atacantes
        if top_ips:
            informe += "\n🎯 ATACANTES PRINCIPALES:\n"
            for ip in top_ips[:5]:
                estado = "🔴 BANEADA" if ip.get('baneada') else "🟡 ACTIVA"
                informe += f"  • {ip.get('ip', 'N/A')} [{estado}] - {ip.get('count', 0)} peticiones - Score: {ip.get('score', 0)}\n"

        # Tipos de ataque
        if tipos:
            informe += "\n📋 TIPOS DE ATAQUE DETECTADOS:\n"
            for t in tipos:
                informe += f"  • {t.get('tipo', 'N/A')}: {t.get('count', 0)} incidencias\n"

        # Recomendaciones
        informe += "\n🛡️ RECOMENDACIONES DE SEGURIDAD:\n"
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
