const VortexChat = {
    abierto: false,
    escuchando: false,
    recognition: null,
    iaDisponible: false,
    iaVerificada: false,

    async iniciar() {
        const fab = document.getElementById('vortex-chat-fab');
        const panel = document.getElementById('vortex-chat-panel');
        const closeBtn = document.getElementById('vortex-chat-close');
        const sendBtn = document.getElementById('vortex-chat-send-btn');
        const input = document.getElementById('vortex-chat-input');
        const micBtn = document.getElementById('vortex-chat-mic-btn');

        fab.addEventListener('click', () => this.togglePanel());
        closeBtn.addEventListener('click', () => this.cerrarPanel());
        sendBtn.addEventListener('click', () => this.enviarMensaje());
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') this.enviarMensaje();
        });
        micBtn.addEventListener('click', () => this.toggleVoz());

        this._inicializarSpeechRecognition();

        try {
            const r = await eel.obtener_estado()();
            const estado = JSON.parse(r);
            this.iaDisponible = estado.ia_cargada === true;
            this.iaVerificada = true;
            if (this.iaDisponible) {
                document.getElementById('vortex-chat-status-text').textContent = 'IA neural en línea.';
            }
        } catch (e) {
            this.iaVerificada = true;
        }
    },

    togglePanel() {
        this.abierto ? this.cerrarPanel() : this.abrirPanel();
    },

    abrirPanel() {
        this.abierto = true;
        const panel = document.getElementById('vortex-chat-panel');
        const fab = document.getElementById('vortex-chat-fab');
        panel.classList.add('open');
        fab.classList.add('active');
        document.getElementById('vortex-chat-input').focus();
    },

    cerrarPanel() {
        this.abierto = false;
        document.getElementById('vortex-chat-panel').classList.remove('open');
        document.getElementById('vortex-chat-fab').classList.remove('active');
        if (this.escuchando) this.toggleVoz();
    },

    async enviarMensaje() {
        const input = document.getElementById('vortex-chat-input');
        const texto = input.value.trim();
        if (!texto) return;

        input.value = '';
        this._agregarMensaje('user', texto);
        this._mostrarTyping();

        try {
            const respuesta = await this._procesarMensaje(texto);
            this._ocultarTyping();
            this._agregarMensaje('bot', respuesta);
        } catch (e) {
            this._ocultarTyping();
            this._agregarMensaje('bot', 'Error al procesar su solicitud. Verifique la conexión con el sistema.');
        }
    },

    async _procesarMensaje(texto) {
        const t = texto.toLowerCase().trim();

        // Comandos directos de acción (no van a la IA, ejecutan funciones locales)
        const comandosAccion = [
            { palabras: ['pdf', 'reporte', 'exportar'], tipo: 'pdf' },
            { palabras: ['informe ia', 'informe rápido', 'generar informe', 'informe reglas'], tipo: 'informe' },
            { palabras: ['cargar modelo', 'cargar ia', 'iniciar ia'], tipo: 'cargar_ia' },
        ];

        for (const cmd of comandosAccion) {
            if (cmd.palabras.some(p => t.includes(p))) {
                return await this._ejecutarAccion(cmd.tipo, texto);
            }
        }

        // Saludos básicos
        if (t.includes('hola') || t.includes('buenos') || t.includes('saludos')) {
            return 'Saludos, operador. Sistema VORTEX en línea. ¿En qué puedo asistirle?';
        }
        if (t.includes('gracias')) {
            return 'Es un placer asistirle, operador. Recuerde que la vigilancia continua es la clave de la seguridad.';
        }
        if (t.includes('quien') && (t.includes('eres') || t.includes('creo'))) {
            return 'Soy VORTEX, un asistente táctico de inteligencia artificial diseñado para el sistema VORTEX Security Intelligence. Mi función es asistirle en el análisis de amenazas, generación de informes y monitoreo de seguridad.';
        }

        // Intentar con la IA local primero
        if (this.iaDisponible) {
            try {
                const r = await eel.preguntar_ia(texto)();
                const data = JSON.parse(r);
                if (data.respuesta) {
                    return data.respuesta;
                }
            } catch (e) {
                // IA falló, continuar con fallback
            }
        }

        // Verificar si la IA está disponible pero no la usamos aún
        if (!this.iaVerificada) {
            try {
                const r = await eel.obtener_estado()();
                const estado = JSON.parse(r);
                this.iaDisponible = estado.ia_cargada === true;
                this.iaVerificada = true;
                if (this.iaDisponible) {
                    // Reintentar con IA ahora que sabemos que está disponible
                    try {
                        const r2 = await eel.preguntar_ia(texto)();
                        const data = JSON.parse(r2);
                        if (data.respuesta) {
                            return data.respuesta;
                        }
                    } catch (e2) {}
                }
            } catch (e) {}
        }

        // Fallback: respuestas basadas en reglas
        if (t.includes('estado') || t.includes('resumen') || t.includes('metricas') || t.includes('dashboard')) {
            if (!VORTEX.datos) return 'No hay datos de análisis disponibles. Primero cargue logs y ejecute un análisis.';
            const r = VORTEX.datos.resumen || {};
            return `Estado actual del sistema:\n• Logs procesados: ${r.total_logs || 0}\n• Amenazas detectadas: ${r.total_amenazas || 0}\n• Nivel de riesgo: ${r.nivel_riesgo || 'N/A'} (Score: ${r.score_riesgo || 0}/100)\n• IPs únicas: ${r.ips_unicas || 0}\n• IPs baneadas: ${r.ips_baneadas || 0}\n• Anomalías IA: ${(VORTEX.datos.anomalias?.total_anomalias) || 0}\n\nRecomendación: ${r.nivel_riesgo === 'ALTO' ? 'Se requiere acción inmediata. Considere generar un informe PDF y revisar las IPs críticas.' : 'El sistema se encuentra en estado estable. Monitoreo continuo activo.'}`;
        }

        if (t.includes('ayuda') || t.includes('help') || t.includes('comandos') || t.includes('que puedes hacer')) {
            return `Comandos disponibles, operador:\n<span class="mat-icon mat-icon-sm" style="vertical-align:middle;">picture_as_pdf</span> "generar PDF/ reporte" - Exportar reporte\n<span class="mat-icon mat-icon-sm" style="vertical-align:middle;">smart_toy</span> "informe IA/ reglas" - Generar informe inteligente\n<span class="mat-icon mat-icon-sm" style="vertical-align:middle;">psychology</span> "cargar IA/ modelo" - Iniciar IA local\n<span class="mat-icon mat-icon-sm" style="vertical-align:middle;">search</span> Haga cualquier pregunta sobre los datos (IPs, amenazas, análisis)\n<span class="mat-icon mat-icon-sm" style="vertical-align:middle;">mic</span> Active el micrófono para comandos por voz\n<span class="mat-icon mat-icon-sm" style="vertical-align:middle;">psychology</span> Cargue el modelo IA desde el panel de acciones para respuestas inteligentes`;
        }

        if (VORTEX.datos) {
            return await this._responderSobreDatos(t);
        }

        return `No reconozco ese comando. Intente "ayuda", haga una pregunta sobre los datos, o cargue el modelo IA desde el panel de acciones para obtener respuestas inteligentes.`;
    },

    async _ejecutarAccion(tipo, textoOriginal) {
        switch (tipo) {
            case 'pdf': {
                if (!VORTEX.datos) return 'No hay datos para generar un reporte. Ejecute un análisis primero.';
                generarPDF();
                return 'Generando reporte PDF. Por favor espere mientras se prepara el documento táctico.';
            }
            case 'informe': {
                if (!VORTEX.datos) return 'No hay datos para generar un informe. Ejecute un análisis primero.';
                generarInformeIA(true);
                return 'Generando informe rápido basado en reglas. Esto tomará solo unos segundos.';
            }
            case 'cargar_ia': {
                cargarModeloIA();
                const self = this;
                const checkInterval = setInterval(async () => {
                    try {
                        const r = await eel.obtener_estado()();
                        const estado = JSON.parse(r);
                        if (estado.ia_cargada) {
                            self.iaDisponible = true;
                            document.getElementById('vortex-chat-status-text').textContent = 'IA neural en línea.';
                            clearInterval(checkInterval);
                        }
                    } catch (e) {}
                }, 2000);
                setTimeout(() => clearInterval(checkInterval), 120000);
                return 'Iniciando carga del modelo de IA local. Este proceso puede tomar varios minutos dependiendo del hardware. Le notificaré cuando esté listo.';
            }
            default:
                return 'Comando reconocido pero no implementado. Consulte "ayuda" para ver las opciones disponibles.';
        }
    },

    async _responderSobreDatos(t) {
        const datos = VORTEX.datos;
        const resumen = datos.resumen || {};

        if (t.includes('ip') || t.includes('ips')) {
            const ips = (datos.top_ips || []).slice(0, 5);
            if (!ips.length) return 'No hay datos de IPs en el análisis actual.';
            let respuesta = 'Top IPs detectadas:\n';
            ips.forEach((ip, i) => {
                respuesta += `${i + 1}. ${ip.ip} — ${ip.count} requests, Score: ${ip.score} ${ip.baneada ? '<span class="mat-icon mat-icon-sm" style="vertical-align:middle;color:var(--red-alert);">block</span> BANEADA' : ''}\n`;
            });
            return respuesta;
        }

        if (t.includes('amenaza') || t.includes('ataque') || t.includes('peligro')) {
            const amenazas = (datos.amenazas || []).slice(0, 5);
            if (!amenazas.length) return 'No se detectaron amenazas activas en este momento.';
            let respuesta = 'Amenazas detectadas:\n';
            amenazas.forEach(a => {
                respuesta += `• ${a.tipo} desde ${a.ip} — Severidad: ${a.severidad}, Score: ${a.score}\n`;
            });
            return respuesta;
        }

        if (t.includes('riesgo') || t.includes('score') || t.includes('nivel')) {
            const score = resumen.score_riesgo || 0;
            const nivel = resumen.nivel_riesgo || 'BAJO';
            return `El nivel de riesgo actual es ${nivel} con una puntuación de ${score}/100.\n${score >= 60 ? '<span class="mat-icon mat-icon-sm" style="vertical-align:middle;color:var(--red-alert);">warning</span> Se recomienda tomar medidas correctivas inmediatas.' : score >= 30 ? '<span class="mat-icon mat-icon-sm" style="vertical-align:middle;color:var(--yellow-warn);">warning</span> Monitoreo reforzado recomendado.' : '<span class="mat-icon mat-icon-sm" style="vertical-align:middle;color:var(--green-neon);">check_circle</span> Sistema dentro de parámetros normales.'}`;
        }

        if (t.includes('anomal') || t.includes('ml') || t.includes('machine learning')) {
            const anomalias = datos.anomalias || {};
            const puntos = anomalias.puntos || [];
            return `Anomalías detectadas por IA:\n• Total de anomalías: ${anomalias.total_anomalias || 0}\n• Puntos anómalos: ${puntos.length}\n${puntos.length > 0 ? '• Método: Isolation Forest + DBSCAN clustering' : '• No se encontraron anomalías significativas.'}`;
        }

        if (t.includes('recomend') || t.includes('suger') || t.includes('que hago')) {
            const nivel = resumen.nivel_riesgo || 'BAJO';
            if (nivel === 'ALTO') {
                return 'Recomendaciones tácticas:\n1. Revise las IPs con score más alto\n2. Genere un informe PDF completo\n3. Ejecute el informe profundo de IA\n4. Considere las IPs baneadas para bloqueo permanente\n5. Active monitoreo continuo';
            }
            return 'El sistema no detecta amenazas críticas en este momento. Sugiero:\n1. Mantener monitoreo continuo\n2. Revisar el dashboard periódicamente\n3. Mantener el modelo de IA cargado para detección temprana';
        }

        return `He analizado los datos actuales. Hay ${resumen.total_logs || 0} logs procesados con ${resumen.total_amenazas || 0} amenazas identificadas. El nivel de riesgo es ${resumen.nivel_riesgo || 'BAJO'}. ¿Sobre qué aspecto específico desea más información?`;
    },

    _agregarMensaje(tipo, texto) {
        const container = document.getElementById('vortex-chat-messages');
        const div = document.createElement('div');
        div.className = `vortex-chat-msg vortex-chat-${tipo}`;

        const icon = tipo === 'bot' ? 'radar' : 'person';
        const time = new Date().toLocaleTimeString('es-MX', { hour: '2-digit', minute: '2-digit' });

        div.innerHTML = `
            <span class="mat-icon mat-icon-sm" style="color:var(--green-neon);">${icon}</span>
            <div>
                <div class="vortex-chat-msg-content">${texto.replace(/\n/g, '<br>')}</div>
                <span class="vortex-chat-msg-time">${time}</span>
            </div>
        `;
        container.appendChild(div);
        container.scrollTop = container.scrollHeight;
    },

    _mostrarTyping() {
        const container = document.getElementById('vortex-chat-messages');
        const div = document.createElement('div');
        div.className = 'vortex-chat-msg vortex-chat-bot';
        div.id = 'vortex-chat-typing-indicator';
        div.innerHTML = `
            <span class="mat-icon mat-icon-sm" style="color:var(--green-neon);">radar</span>
            <div class="vortex-chat-msg-content vortex-chat-typing">
                <span></span><span></span><span></span>
            </div>
        `;
        container.appendChild(div);
        container.scrollTop = container.scrollHeight;
    },

    _ocultarTyping() {
        const el = document.getElementById('vortex-chat-typing-indicator');
        if (el) el.remove();
    },

    _inicializarSpeechRecognition() {
        const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
        if (!SpeechRecognition) {
            document.getElementById('vortex-chat-mic-btn').style.display = 'none';
            return;
        }

        this.recognition = new SpeechRecognition();
        this.recognition.lang = 'es-MX';
        this.recognition.continuous = false;
        this.recognition.interimResults = false;

        this.recognition.onresult = (event) => {
            const texto = event.results[0][0].transcript;
            this._agregarMensaje('user', `<span class="mat-icon mat-icon-sm" style="vertical-align:middle;">mic</span> ${texto}`);
            document.getElementById('vortex-chat-input').value = texto;
            this.toggleVoz();
            setTimeout(() => this.enviarMensaje(), 300);
        };

        this.recognition.onerror = () => {
            this.toggleVoz();
            this._agregarMensaje('bot', 'No pude entender el comando de voz. Intente de nuevo o escriba el comando.');
        };

        this.recognition.onend = () => {
            if (this.escuchando) this.escuchando = false;
            this._actualizarEstadoVoz();
        };
    },

    toggleVoz() {
        if (!this.recognition) return;

        if (this.escuchando) {
            this.recognition.stop();
            this.escuchando = false;
        } else {
            try {
                this.recognition.start();
                this.escuchando = true;
            } catch (e) {
                this.escuchando = false;
            }
        }
        this._actualizarEstadoVoz();
    },

    _actualizarEstadoVoz() {
        const micBtn = document.getElementById('vortex-chat-mic-btn');
        const statusText = document.getElementById('vortex-chat-status-text');
        const statusDot = document.querySelector('.vortex-chat-status-dot');

        if (this.escuchando) {
            micBtn.classList.add('listening');
            micBtn.querySelector('.mat-icon').textContent = 'mic_off';
            statusText.textContent = 'Escuchando... Hable ahora.';
            if (statusDot) statusDot.classList.add('listening');
        } else {
            micBtn.classList.remove('listening');
            micBtn.querySelector('.mat-icon').textContent = 'mic';
            statusText.textContent = 'Sistema listo. Voz inactiva.';
            if (statusDot) statusDot.classList.remove('listening');
        }
    }
};

document.addEventListener('DOMContentLoaded', () => {
    VortexChat.iniciar();
});
