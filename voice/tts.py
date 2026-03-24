"""
VORTEX Security Intelligence - Sistema de Voz Offline
Usa pyttsx3 para narración estilo IA militar/táctico.
"""

import threading


class VortexVoz:
    """Sistema de voz táctico para VORTEX."""

    def __init__(self, habilitado=True):
        self.habilitado = habilitado
        self.motor = None
        self._lock = threading.Lock()
        self._inicializar()

    def _inicializar(self):
        """Inicializa el motor de voz."""
        try:
            import pyttsx3
            self.motor = pyttsx3.init()
            # Configurar voz
            self.motor.setProperty('rate', 160)     # Velocidad
            self.motor.setProperty('volume', 0.9)    # Volumen

            # Intentar usar voz en español
            voces = self.motor.getProperty('voices')
            for voz in voces:
                if 'spanish' in voz.name.lower() or 'español' in voz.name.lower() or 'es' in voz.id.lower():
                    self.motor.setProperty('voice', voz.id)
                    break
            else:
                # Si no hay voz en español, usar la primera disponible
                if voces:
                    self.motor.setProperty('voice', voces[0].id)

        except Exception as e:
            print(f"[VORTEX VOZ] Error al inicializar motor de voz: {e}")
            self.motor = None

    def hablar(self, texto):
        """Habla el texto dado en un hilo separado."""
        if not self.habilitado or not self.motor:
            return

        def _hablar_thread():
            with self._lock:
                try:
                    self.motor.say(texto)
                    self.motor.runAndWait()
                except Exception as e:
                    print(f"[VORTEX VOZ] Error al hablar: {e}")

        thread = threading.Thread(target=_hablar_thread, daemon=True)
        thread.start()

    def hablar_sincrono(self, texto):
        """Habla el texto de forma síncrona."""
        if not self.habilitado or not self.motor:
            return
        with self._lock:
            try:
                self.motor.say(texto)
                self.motor.runAndWait()
            except Exception as e:
                print(f"[VORTEX VOZ] Error al hablar: {e}")

    def toggle(self):
        """Activa/desactiva el sistema de voz."""
        self.habilitado = not self.habilitado
        estado = "activado" if self.habilitado else "desactivado"
        print(f"[VORTEX VOZ] Sistema de voz {estado}")
        if self.habilitado:
            self.hablar("Sistema de voz activado")
        return self.habilitado

    def estado(self):
        """Retorna el estado actual del sistema de voz."""
        return {
            'habilitado': self.habilitado,
            'motor_disponible': self.motor is not None
        }

    # ══════════════════════════════════════════════════════
    # EVENTOS TÁCTICOS
    # ══════════════════════════════════════════════════════

    def evento_inicio_sistema(self):
        """Narración al iniciar VORTEX."""
        self.hablar(
            "VORTEX Security Intelligence inicializado. "
            "Todos los sistemas operativos. "
            "Módulo de defensa activo. "
            "Esperando instrucciones del operador."
        )

    def evento_inicio_analisis(self, total_logs):
        """Narración al iniciar análisis."""
        self.hablar(
            f"Iniciando análisis táctico de {total_logs} registros de seguridad. "
            "Activando motores de detección. "
            "Procesando datos."
        )

    def evento_deteccion_critica(self, tipo_ataque, ip):
        """Narración al detectar amenaza crítica."""
        self.hablar(
            f"¡Alerta crítica! Se ha detectado un ataque de tipo: {tipo_ataque}. "
            f"Origen: {ip}. "
            "Nivel de amenaza elevado. Requiere atención inmediata."
        )

    def evento_resumen_final(self, resumen):
        """Narración del resumen final de análisis."""
        total = resumen.get('total_logs', 0)
        amenazas = resumen.get('total_amenazas', 0)
        nivel = resumen.get('nivel_riesgo', 'BAJO')
        score = resumen.get('score_riesgo', 0)

        self.hablar(
            f"Análisis completo. Se procesaron {total} registros. "
            f"Se identificaron {amenazas} amenazas potenciales. "
            f"Nivel de riesgo general: {nivel}. "
            f"Puntuación de riesgo: {score} de 100. "
            f"{'Se recomienda acción inmediata.' if nivel == 'ALTO' else 'Sistema en monitoreo continuo.'}"
        )

    def evento_reporte_generado(self):
        """Narración al generar reporte."""
        self.hablar(
            "Reporte de inteligencia generado exitosamente. "
            "Documento disponible para descarga."
        )


# Instancia global
_voz_instance = None


def obtener_voz(habilitado=True):
    """Obtiene o crea la instancia global del sistema de voz."""
    global _voz_instance
    if _voz_instance is None:
        _voz_instance = VortexVoz(habilitado)
    return _voz_instance
