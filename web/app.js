/**
 * ═══════════════════════════════════════════════════════════════
 * VORTEX Security Intelligence - App Principal (Frontend)
 * Lógica del dashboard, ingesta, análisis y comunicación con Eel
 * ═══════════════════════════════════════════════════════════════
 */

// ── Estado global del frontend ──
const VORTEX = {
    datos: null,
    analizando: false,
    vozHabilitada: true,
    mapaInicializado: false,
    consolaLineas: [],
    maxConsolaLineas: 200,
};

// ══════════════════════════════════════════════════════════════
// BOOT SEQUENCE
// ══════════════════════════════════════════════════════════════

const BOOT_MESSAGES = [
    { text: '> ARRANCANDO VORTEX CORE...', delay: 400 },
    { text: '> INICIALIZANDO SISTEMA DE DEFENSA...', delay: 600 },
    { text: '> CARGANDO RED NEURONAL...', delay: 500 },
    { text: '> CALIBRANDO DETECCIÓN DE AMENAZAS...', delay: 450 },
    { text: '> ESTABLECIENDO ENLACE SEGURO...', delay: 500 },
    { text: '> ACTIVANDO VIGILANCIA OJO DE DIOS...', delay: 550 },
    { text: '> CARGANDO MODELOS DE MACHINE LEARNING...', delay: 400 },
    { text: '> SISTEMA LISTO ✓', delay: 300 },
];

async function ejecutarBootSequence() {
    const terminal = document.getElementById('boot-terminal');
    const progressBar = document.getElementById('boot-progress-bar');
    const totalSteps = BOOT_MESSAGES.length;

    for (let i = 0; i < totalSteps; i++) {
        const msg = BOOT_MESSAGES[i];
        
        // Crear línea
        const line = document.createElement('div');
        line.className = 'boot-line';
        line.innerHTML = `${msg.text}`;
        terminal.appendChild(line);

        // Hacer visible con animación
        await sleep(100);
        line.classList.add('visible');

        // Agregar cursor solo a la última línea
        const prevCursors = terminal.querySelectorAll('.cursor');
        prevCursors.forEach(c => c.remove());
        if (i < totalSteps - 1) {
            const cursor = document.createElement('span');
            cursor.className = 'cursor';
            line.appendChild(cursor);
        }

        // Actualizar barra de progreso
        const progreso = ((i + 1) / totalSteps) * 100;
        progressBar.style.width = `${progreso}%`;

        await sleep(msg.delay);
    }

    // Esperar un momento antes de transicionar
    await sleep(800);

    // Ocultar boot screen
    document.getElementById('boot-screen').classList.add('hidden');

    // Mostrar UI principal
    document.getElementById('main-header').style.display = '';
    document.getElementById('main-content').style.display = '';
    document.getElementById('main-footer').style.display = '';

    // NO inicializar el mapa aquí: su contenedor (content-section) está
    // oculto (display:none) y Leaflet no puede calcular el tamaño de los tiles.
    // Se inicializa cuando renderizarDashboard() muestra la sección.

    // Iniciar reloj
    actualizarReloj();
    setInterval(actualizarReloj, 1000);

    // Evento de voz: Inicio de sistema
    setTimeout(() => {
        VortexVoz.eventoInicioSistema();
    }, 1000);
}

// ══════════════════════════════════════════════════════════════
// UTILIDADES
// ══════════════════════════════════════════════════════════════

function sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
}

function actualizarReloj() {
    const now = new Date();
    const timeStr = now.toLocaleTimeString('es-MX', { hour12: false });
    const dateStr = now.toLocaleDateString('es-MX');
    const el = document.getElementById('clock-display');
    if (el) el.textContent = `${dateStr} ${timeStr}`;
    const footer = document.getElementById('footer-clock');
    if (footer) footer.textContent = timeStr;
}

function mostrarToast(mensaje, tipo = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast toast-${tipo}`;
    toast.textContent = mensaje;
    container.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(40px)';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

function agregarLineaConsola(severity, mensaje) {
    const consola = document.getElementById('live-console');
    if (!consola) return;

    const now = new Date();
    const time = now.toLocaleTimeString('es-MX', { hour12: false });

    const severityClass = severity === 'CRITICAL' ? 'critical' :
                         severity === 'HIGH' ? 'high' :
                         severity === 'WARNING' ? 'warning' : 'info';

    const line = document.createElement('div');
    line.className = 'console-line';
    line.innerHTML = `
        <span class="console-time">[${time}]</span>
        <span class="console-severity ${severityClass}">${severity}</span>
        <span class="console-msg">${escapeHtml(mensaje)}</span>
    `;

    consola.appendChild(line);

    // Limitar líneas
    VORTEX.consolaLineas.push(line);
    if (VORTEX.consolaLineas.length > VORTEX.maxConsolaLineas) {
        const old = VORTEX.consolaLineas.shift();
        old.remove();
    }

    // Auto-scroll
    consola.scrollTop = consola.scrollHeight;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function obtenerBadgeSeveridad(severidad) {
    const sev = (severidad || 'INFO').toUpperCase();
    const clases = {
        'CRITICAL': 'badge-critical',
        'HIGH': 'badge-high',
        'MEDIUM': 'badge-medium',
        'LOW': 'badge-low',
        'INFO': 'badge-info',
    };
    return `<span class="badge ${clases[sev] || 'badge-info'}">${sev}</span>`;
}

// ══════════════════════════════════════════════════════════════
// INGESTA DE LOGS
// ══════════════════════════════════════════════════════════════

function inicializarIngesta() {
    const textarea = document.getElementById('log-textarea');
    const btnAnalyze = document.getElementById('btn-analyze');
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    const btnLoadDefault = document.getElementById('btn-load-default');
    const btnLoadSample = document.getElementById('btn-load-sample');

    // Habilitar botón cuando hay texto
    textarea.addEventListener('input', () => {
        btnAnalyze.disabled = !textarea.value.trim();
    });

    // Drag & Drop
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('dragover');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        const file = e.dataTransfer.files[0];
        if (file) leerArchivo(file);
    });

    dropZone.addEventListener('click', () => fileInput.click());

    // File input
    fileInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (file) leerArchivo(file);
    });

    // Cargar desde .env
    btnLoadDefault.addEventListener('click', async () => {
        agregarLineaConsola('INFO', 'Cargando logs desde ruta .env...');
        try {
            const result = await eel.leer_logs_archivo()();
            const data = JSON.parse(result);
            if (data.exito) {
                textarea.value = data.contenido;
                btnAnalyze.disabled = false;
                mostrarToast(`${data.total_lineas} líneas cargadas desde .env`, 'success');
                agregarLineaConsola('INFO', `${data.total_lineas} líneas cargadas desde archivo .env`);
            } else {
                mostrarToast(data.error || 'Error al cargar archivo', 'error');
                agregarLineaConsola('WARNING', data.error || 'Archivo no encontrado');
            }
        } catch (e) {
            mostrarToast('Error al comunicarse con el backend', 'error');
        }
    });

    // Cargar sample
    btnLoadSample.addEventListener('click', () => {
        cargarLogEjemplo();
    });

    // Botón analizar
    btnAnalyze.addEventListener('click', () => {
        ejecutarAnalisis(textarea.value);
    });

    // Generar PDF
    document.getElementById('btn-generate-pdf').addEventListener('click', generarPDF);
    
    // Generar informe IA
    document.getElementById('btn-generate-ia').addEventListener('click', generarInformeIA);

    // Abrir PDF
    document.getElementById('btn-open-pdf').addEventListener('click', async () => {
        try {
            const result = await eel.abrir_reporte_pdf()();
            const data = JSON.parse(result);
            if (data.exito) {
                mostrarToast(`Abriendo: ${data.archivo}`, 'success');
            } else {
                mostrarToast(data.error, 'error');
            }
        } catch (e) {
            mostrarToast('Error al abrir PDF', 'error');
        }
    });

    // Toggle voz
    document.getElementById('voice-toggle').addEventListener('change', (e) => {
        const estado = VortexVoz.toggle();
        mostrarToast(`Voz ${estado ? 'activada' : 'desactivada'}`, 'info');
        
        // Opcional: sincronizar con backend
        try { eel.toggle_voz()(); } catch(e) {}
    });

    // Limpiar consola
    document.getElementById('btn-clear-console').addEventListener('click', () => {
        const consola = document.getElementById('live-console');
        consola.innerHTML = '';
        VORTEX.consolaLineas = [];
        agregarLineaConsola('INFO', 'Consola limpiada');
    });

    // Refresh mapa
    document.getElementById('btn-refresh-map').addEventListener('click', () => {
        if (VORTEX.datos && VORTEX.datos.geo_data) {
            actualizarMapa(VORTEX.datos.geo_data);
            mostrarToast('Mapa actualizado', 'info');
        }
    });

    // Reportes IA / Reglas
    document.getElementById('btn-generate-ia').addEventListener('click', () => generarInformeIA(false));
    document.getElementById('btn-generate-rules').addEventListener('click', () => generarInformeIA(true));

    // Cargar IA
    document.getElementById('btn-load-ia').addEventListener('click', cargarModeloIA);

    // Configurar botones de voz en contenedores
    document.querySelectorAll('.btn-voice-read').forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.getAttribute('data-target');
            const target = document.getElementById(targetId);
            if (target) {
                // Obtener texto limpio (sin tags)
                const texto = target.innerText || target.textContent;
                VortexVoz.hablar(texto);
                mostrarToast('Leyendo sección...', 'info');
            }
        });
    });
}

function leerArchivo(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
        const textarea = document.getElementById('log-textarea');
        textarea.value = e.target.result;
        document.getElementById('btn-analyze').disabled = false;
        mostrarToast(`Archivo "${file.name}" cargado (${(file.size / 1024).toFixed(1)} KB)`, 'success');
        agregarLineaConsola('INFO', `Archivo cargado: ${file.name}`);
    };
    reader.readAsText(file);
}

function cargarLogEjemplo() {
    // Generar logs de ejemplo directamente
    const sampleLogs = generarLogsEjemplo();
    document.getElementById('log-textarea').value = sampleLogs;
    document.getElementById('btn-analyze').disabled = false;
    mostrarToast('Logs de ejemplo cargados', 'success');
    agregarLineaConsola('INFO', 'Logs de ejemplo cargados en textarea');
}

function generarLogsEjemplo() {
    const now = new Date();
    const fmt = (d) => {
        return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')} ${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}:${String(d.getSeconds()).padStart(2,'0')}`;
    };

    const lines = [];
    const ataques = [
        { sev: 'CRITICAL', tipo: 'SQL_INJECTION', ip: '185.220.101.34', ban: ' [BANEADO POR 24h]', uri: "/api/users?id=1' UNION SELECT * FROM users--", ua: 'sqlmap/1.7.2#stable' },
        { sev: 'CRITICAL', tipo: 'SQL_INJECTION', ip: '185.220.101.34', ban: ' [BANEADO POR 24h]', uri: "/api/login?user=admin' OR '1'='1", ua: 'sqlmap/1.7.2#stable' },
        { sev: 'HIGH', tipo: 'XSS_ATTACK', ip: '45.33.32.156', ban: '', uri: "/search?q=<script>alert('XSS')</script>", ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
        { sev: 'WARNING', tipo: 'DIRECTORY_TRAVERSAL', ip: '91.121.87.10', ban: '', uri: '/files?path=../../../../etc/passwd', ua: 'python-requests/2.28.0' },
        { sev: 'CRITICAL', tipo: 'RECONNAISSANCE', ip: '58.218.92.37', ban: '', uri: '/.env', ua: 'Go-http-client/1.1' },
        { sev: 'CRITICAL', tipo: 'RECONNAISSANCE', ip: '58.218.92.37', ban: '', uri: '/.git/config', ua: 'Go-http-client/1.1' },
        { sev: 'HIGH', tipo: 'BOT_SCAN', ip: '71.6.135.131', ban: '', uri: '/api/v1/users', ua: 'Nmap Scripting Engine' },
        { sev: 'CRITICAL', tipo: 'BRUTE_FORCE', ip: '46.101.245.89', ban: ' [BANEADO POR 1h]', uri: '/login', ua: 'Mozilla/5.0 (X11; Linux x86_64)' },
        { sev: 'CRITICAL', tipo: 'BRUTE_FORCE', ip: '46.101.245.89', ban: ' [BANEADO POR 1h]', uri: '/login', ua: 'Mozilla/5.0 (X11; Linux x86_64)' },
        { sev: 'WARNING', tipo: 'RATE_LIMIT', ip: '103.152.220.44', ban: '', uri: '/api/search', ua: 'curl/7.88.1' },
        { sev: 'HIGH', tipo: 'HONEYPOT', ip: '195.154.179.3', ban: '', uri: '/trap', ua: 'Nikto/2.1.6' },
        { sev: 'HIGH', tipo: 'HONEYPOT', ip: '195.154.179.3', ban: '', uri: '/phpinfo.php', ua: 'Nikto/2.1.6' },
        { sev: 'INFO', tipo: 'NORMAL', ip: '200.68.120.15', ban: '', uri: '/index.html', ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/121.0.0.0' },
        { sev: 'INFO', tipo: 'NORMAL', ip: '201.141.95.22', ban: '', uri: '/api/products', ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15' },
        { sev: 'INFO', tipo: 'NORMAL', ip: '168.196.88.200', ban: '', uri: '/api/categories', ua: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)' },
        { sev: 'HIGH', tipo: 'SQL_INJECTION', ip: '82.165.77.211', ban: '', uri: "/api/products?id=1;DROP TABLE products;--", ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
        { sev: 'HIGH', tipo: 'XSS_ATTACK', ip: '213.32.75.92', ban: '', uri: '/profile?bio=<svg onload=alert(1)>', ua: 'Mozilla/5.0 (Android 13; Mobile; rv:109.0)' },
        { sev: 'CRITICAL', tipo: 'BRUTE_FORCE', ip: '178.128.123.45', ban: ' [BANEADO POR 24h]', uri: '/api/auth/login', ua: 'python-requests/2.31.0' },
        { sev: 'CRITICAL', tipo: 'BRUTE_FORCE', ip: '178.128.123.45', ban: ' [BANEADO POR 24h]', uri: '/api/auth/login', ua: 'python-requests/2.31.0' },
        { sev: 'CRITICAL', tipo: 'BRUTE_FORCE', ip: '178.128.123.45', ban: ' [BANEADO POR 24h]', uri: '/api/auth/login', ua: 'python-requests/2.31.0' },
        { sev: 'WARNING', tipo: 'RECONNAISSANCE', ip: '64.62.197.18', ban: '', uri: '/admin/dashboard', ua: 'CensysInspect/1.1' },
        { sev: 'HIGH', tipo: 'BOT_SCAN', ip: '104.248.185.94', ban: '', uri: '/graphql', ua: 'python-requests/2.31.0' },
        { sev: 'HIGH', tipo: 'DIRECTORY_TRAVERSAL', ip: '128.199.55.201', ban: '', uri: '/static/../../../proc/self/environ', ua: 'httpx/0.25.0' },
        { sev: 'CRITICAL', tipo: 'RECONNAISSANCE', ip: '80.82.77.139', ban: '', uri: '/config.php.bak', ua: 'masscan/1.3' },
        { sev: 'INFO', tipo: 'NORMAL', ip: '190.25.44.100', ban: '', uri: '/products/list', ua: 'Firefox/121.0' },
        { sev: 'WARNING', tipo: 'RATE_LIMIT_ABUSE', ip: '156.67.111.23', ban: '', uri: '/api/v2/data', ua: 'wget/1.21' },
        { sev: 'WARNING', tipo: 'RATE_LIMIT_ABUSE', ip: '156.67.111.23', ban: '', uri: '/api/v2/data', ua: 'wget/1.21' },
        { sev: 'HIGH', tipo: 'HONEYPOT', ip: '162.243.128.55', ban: '', uri: '/.aws/credentials', ua: 'nuclei/v3.0.4' },
        { sev: 'CRITICAL', tipo: 'SQL_INJECTION', ip: '77.247.181.163', ban: '', uri: "/api/search?q=1' AND SLEEP(5)--", ua: 'sqlmap/1.7.2#stable' },
        { sev: 'INFO', tipo: 'NORMAL', ip: '143.198.45.67', ban: '', uri: '/about', ua: 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64) Firefox/121.0' },
    ];

    ataques.forEach((a, i) => {
        const d = new Date(now.getTime() - (ataques.length - i) * 45000);
        const method = a.uri.includes('login') || a.uri.includes('auth') ? 'POST' : 'GET';
        lines.push(`[${fmt(d)}] [${a.sev}] Type: ${a.tipo} | IP: ${a.ip}${a.ban} | URI: ${a.uri} | Method: ${method} | UA: ${a.ua}`);
    });

    return lines.join('\n');
}

// ══════════════════════════════════════════════════════════════
// ANÁLISIS
// ══════════════════════════════════════════════════════════════

async function ejecutarAnalisis(textoLogs) {
    if (VORTEX.analizando) return;
    VORTEX.analizando = true;

    const btnAnalyze = document.getElementById('btn-analyze');
    const progress = document.getElementById('analysis-progress');
    const progressText = document.getElementById('progress-text');

    btnAnalyze.disabled = true;
    btnAnalyze.innerHTML = '<span class="spinner"></span> Analizando...';
    progress.classList.add('active');

    const linesCount = (textoLogs.match(/\n/g) || []).length + 1;
    VortexVoz.eventoInicioAnalisis(linesCount);

    agregarLineaConsola('INFO', '⚡ Iniciando análisis de seguridad...');

    // Limpiar resultados previos
    if (document.getElementById('ia-report-content')) document.getElementById('ia-report-content').innerHTML = '';
    if (document.getElementById('perfiles-list')) document.getElementById('perfiles-list').innerHTML = '';
    
    // Resetear contadores visuales (metrics)
    const metrics = ['stat-total-logs', 'stat-amenazas', 'stat-unicas', 'stat-baneadas'];
    metrics.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.textContent = '0';
    });

    const pasos = [
        'Parseando logs de seguridad...',
        'Ejecutando motor de detección de ataques...',
        'Iniciando análisis de Machine Learning...',
        'Geolocalizando direcciones IP...',
        'Generando perfiles de atacantes...',
        'Compilando resultados...',
    ];

    // Simular progreso visual mientras se procesa
    let pasoActual = 0;
    const intervalo = setInterval(() => {
        if (pasoActual < pasos.length) {
            progressText.textContent = `⚡ ${pasos[pasoActual]}`;
            agregarLineaConsola('INFO', pasos[pasoActual]);
            pasoActual++;
        }
    }, 600);

    try {
        // Llamar al backend
        const resultado = await eel.analizar_logs(textoLogs)();
        clearInterval(intervalo);

        const datos = JSON.parse(resultado);

        if (datos.error) {
            mostrarToast(`Error: ${datos.error}`, 'error');
            agregarLineaConsola('CRITICAL', `Error en análisis: ${datos.error}`);
            resetearAnalisis();
            return;
        }

        // Guardar datos
        VORTEX.datos = datos;

        // Renderizar dashboard
        renderizarDashboard(datos);

        // Habilitar botones
        document.getElementById('btn-generate-pdf').disabled = false;
        document.getElementById('btn-generate-ia').disabled = false;
        document.getElementById('btn-generate-rules').disabled = false;
        document.getElementById('btn-open-pdf').disabled = false;

        mostrarToast('✅ Análisis completado exitosamente', 'success');
        agregarLineaConsola('INFO', `✅ Análisis completo: ${datos.resumen.total_logs} logs, ${datos.resumen.total_amenazas} amenazas`);

        // Evento de voz: Resumen
        VortexVoz.eventoResumenFinal(datos.resumen);

        // Actualizar footer
        document.getElementById('footer-status').textContent = 
            `Estado: ${datos.resumen.total_logs} logs | ${datos.resumen.total_amenazas} amenazas | Riesgo: ${datos.resumen.nivel_riesgo}`;

    } catch (e) {
        clearInterval(intervalo);
        mostrarToast(`Error de comunicación: ${e.message}`, 'error');
        agregarLineaConsola('CRITICAL', `Error de comunicación: ${e.message}`);
    }

    resetearAnalisis();
}

function resetearAnalisis() {
    VORTEX.analizando = false;
    const btnAnalyze = document.getElementById('btn-analyze');
    btnAnalyze.disabled = false;
    btnAnalyze.innerHTML = '⚡ Iniciar Análisis';
    document.getElementById('analysis-progress').classList.remove('active');
}

// ══════════════════════════════════════════════════════════════
// RENDERIZAR DASHBOARD
// ══════════════════════════════════════════════════════════════

function renderizarDashboard(datos) {
    const resumen = datos.resumen || {};

    // Mostrar secciones
    ['metrics-section', 'content-section', 'charts-section', 'ia-section', 'attackers-section'].forEach(id => {
        document.getElementById(id).style.display = '';
    });

    // Inicializar mapa ahora que su contenedor es visible
    if (!VORTEX.mapaInicializado && typeof inicializarMapa === 'function') {
        setTimeout(() => {
            inicializarMapa();
            VORTEX.mapaInicializado = true;
        }, 200);
    }

    // ── Métricas ──
    animarNumero('m-total-logs', resumen.total_logs || 0);
    animarNumero('m-amenazas', resumen.total_amenazas || 0);
    animarNumero('m-score', resumen.score_riesgo || 0);
    animarNumero('m-ips', resumen.ips_unicas || 0);
    animarNumero('m-baneadas', resumen.ips_baneadas || 0);

    const anomalias = datos.anomalias || {};
    animarNumero('m-anomalias', anomalias.total_anomalias || 0);

    // Nivel de riesgo
    const nivel = resumen.nivel_riesgo || 'BAJO';
    document.getElementById('m-nivel').textContent = `NIVEL: ${nivel}`;

    // ── Score CSS ──
    const scoreEl = document.getElementById('m-score');
    const score = resumen.score_riesgo || 0;
    if (score >= 60) {
        scoreEl.className = 'metric-value red';
    } else if (score >= 30) {
        scoreEl.className = 'metric-value yellow';
    } else {
        scoreEl.className = 'metric-value green';
    }

    // ── Indicador de riesgo ──
    renderizarRiesgo(resumen.score_riesgo || 0, nivel);

    // ── Top IPs ──
    renderizarTablaIPs(datos.top_ips || []);

    // ── Tipos de ataque ──
    renderizarTablaTipos(datos.tipos_ataque || []);

    // ── Top URIs ──
    renderizarTablaURIs(datos.top_uris || []);

    // ── Perfiles atacantes ──
    renderizarPerfilesAtacantes(datos.perfiles_atacantes || []);

    // ── Gráficas ──
    if (typeof renderizarGraficas === 'function') {
        renderizarGraficas(datos);
    }

    // ── Mapa ── (delay extra para asegurar que Leaflet ya recalculó)
    if (datos.geo_data && typeof actualizarMapa === 'function') {
        setTimeout(() => actualizarMapa(datos.geo_data), 800);
    }

    // ── Consola: mostrar amenazas top ──
    const amenazasTop = (datos.amenazas || []).slice(0, 10);
    amenazasTop.forEach(a => {
        const sev = a.severidad || 'INFO';
        agregarLineaConsola(sev, `${a.tipo} | IP: ${a.ip} | URI: ${a.uri} | Score: ${a.score}`);
    });
}

function animarNumero(elementId, targetValue) {
    const el = document.getElementById(elementId);
    if (!el) return;

    const start = parseInt(el.textContent) || 0;
    const duration = 800;
    const startTime = performance.now();

    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        // Ease out cubic
        const eased = 1 - Math.pow(1 - progress, 3);
        const current = Math.round(start + (targetValue - start) * eased);
        el.textContent = current;
        if (progress < 1) requestAnimationFrame(update);
    }

    requestAnimationFrame(update);
}

function renderizarRiesgo(score, nivel) {
    // Aguja del gauge: -90deg (0) a 90deg (100)
    const angulo = -90 + (score / 100) * 180;
    document.getElementById('risk-needle').style.transform = `translateX(-50%) rotate(${angulo}deg)`;

    const scoreEl = document.getElementById('risk-score');
    const labelEl = document.getElementById('risk-label');

    scoreEl.textContent = score;
    labelEl.textContent = nivel;

    // Colores según nivel
    const riskClass = score >= 60 ? 'risk-high' : score >= 30 ? 'risk-medium' : 'risk-low';
    scoreEl.className = `risk-score ${riskClass}`;
    labelEl.className = `risk-label ${riskClass}`;
}

function renderizarTablaIPs(topIps) {
    const tbody = document.querySelector('#table-top-ips tbody');
    tbody.innerHTML = '';

    topIps.slice(0, 15).forEach(ip => {
        const tr = document.createElement('tr');
        const estado = ip.baneada ? '<span class="badge badge-banned">BAN</span>' : obtenerBadgeSeveridad(ip.severidad);
        tr.innerHTML = `
            <td title="${ip.tipos ? ip.tipos.join(', ') : ''}">${ip.ip}</td>
            <td>${ip.count}</td>
            <td>${ip.score}</td>
            <td>${estado}</td>
        `;
        tbody.appendChild(tr);
    });
}

function renderizarTablaTipos(tipos) {
    const tbody = document.querySelector('#table-attack-types tbody');
    tbody.innerHTML = '';

    tipos.forEach(tipo => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${tipo.tipo}</td>
            <td>${tipo.count}</td>
        `;
        tbody.appendChild(tr);
    });
}

function renderizarTablaURIs(uris) {
    const tbody = document.querySelector('#table-top-uris tbody');
    tbody.innerHTML = '';

    uris.slice(0, 15).forEach(uri => {
        const tr = document.createElement('tr');
        const uriText = uri.uri.length > 40 ? uri.uri.substring(0, 37) + '...' : uri.uri;
        tr.innerHTML = `
            <td title="${escapeHtml(uri.uri)}">${escapeHtml(uriText)}</td>
            <td>${uri.count}</td>
        `;
        tbody.appendChild(tr);
    });
}

function renderizarPerfilesAtacantes(perfiles) {
    const tbody = document.querySelector('#table-attackers tbody');
    tbody.innerHTML = '';

    perfiles.forEach(p => {
        const tr = document.createElement('tr');
        const estado = p.baneada ? '<span class="badge badge-banned">BANEADA</span>' : '<span class="badge badge-high">ACTIVA</span>';
        tr.innerHTML = `
            <td>${p.ip}</td>
            <td>${p.score_riesgo}</td>
            <td>${p.total_requests}</td>
            <td>${p.clasificacion}</td>
            <td>${(p.tipos_ataque || []).join(', ')}</td>
            <td>${estado}</td>
        `;
        tbody.appendChild(tr);
    });
}

// ══════════════════════════════════════════════════════════════
// PDF & IA
// ══════════════════════════════════════════════════════════════

async function generarPDF() {
    const btn = document.getElementById('btn-generate-pdf');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Generando...';
    agregarLineaConsola('INFO', '📄 Generando reporte PDF...');

    try {
        const result = await eel.generar_reporte_pdf()();
        const data = JSON.parse(result);

        if (data.exito) {
            mostrarToast(`✅ PDF generado: ${data.nombre}`, 'success');
            agregarLineaConsola('INFO', `✅ Reporte PDF generado: ${data.nombre}`);
            VortexVoz.eventoReporteGenerado();
        } else {
            mostrarToast(`Error: ${data.error}`, 'error');
            agregarLineaConsola('CRITICAL', `Error PDF: ${data.error}`);
        }
    } catch (e) {
        mostrarToast(`Error: ${e.message}`, 'error');
    }

    btn.disabled = false;
    btn.innerHTML = '📄 Generar Reporte PDF';
}

async function generarInformeIA(usarReglas = false) {
    const btn = usarReglas ? document.getElementById('btn-generate-rules') : document.getElementById('btn-generate-ia');
    const labelOriginal = btn.innerHTML;

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Generando...';
    
    if (usarReglas) {
        agregarLineaConsola('INFO', '📋 Generando informe rápido basado en reglas...');
    } else {
        agregarLineaConsola('INFO', '🤖 Generando informe profundo de IA...');
    }

    try {
        const result = await eel.generar_reporte_ia(usarReglas)();
        const data = JSON.parse(result);

        if (data.informe_ejecutivo) {
            document.getElementById('ia-report-content').textContent = data.informe_ejecutivo;
            mostrarToast(`✅ Informe IA generado (${data.generado_por})`, 'success');
            agregarLineaConsola('INFO', `✅ Informe IA generado por: ${data.generado_por}`);

            // Scroll al informe
            document.getElementById('ia-section').scrollIntoView({ behavior: 'smooth', block: 'start' });
        } else if (data.error) {
            mostrarToast(`Error: ${data.error}`, 'error');
        }
    } catch (e) {
        mostrarToast(`Error: ${e.message}`, 'error');
    }

    btn.disabled = false;
    btn.innerHTML = labelOriginal;
    actualizarEstadoIA();
}

/**
 * Actualiza el estado visual de la IA en la UI
 */
async function actualizarEstadoIA() {
    try {
        const result = await eel.obtener_estado()();
        const estado = JSON.parse(result);
        
        const dot = document.getElementById('ia-status-dot');
        const msg = document.getElementById('ia-status-msg');
        const btn = document.getElementById('btn-load-ia');

        if (estado.ia_cargada) {
            dot.className = 'ia-status-dot online';
            msg.textContent = 'IA LLM: Cargada (Activa)';
            btn.style.display = 'none';
        } else {
            dot.className = 'ia-status-dot';
            msg.textContent = 'IA LLM: No cargada';
            btn.style.display = 'inline-block';
        }
    } catch (e) {
        console.error("Error al obtener estado IA", e);
    }
}

/**
 * Carga el modelo de IA local (proceso pesado)
 */
async function cargarModeloIA() {
    const btn = document.getElementById('btn-load-ia');
    const dot = document.getElementById('ia-status-dot');
    const msg = document.getElementById('ia-status-msg');

    btn.disabled = true;
    btn.textContent = 'Cargando...';
    dot.className = 'ia-status-dot loading';
    msg.textContent = 'IA LLM: Cargando modelo (1GB+)...';
    
    agregarLineaConsola('INFO', '🤖 Iniciando descarga/carga de modelo IA local. Esto puede tardar varios minutos...');
    mostrarToast('Iniciando carga de modelo IA (1GB+). Por favor espera.', 'info');

    try {
        const result = await eel.cargar_modelo_ia()();
        const data = JSON.parse(result);

        if (data.cargado) {
            mostrarToast('✅ Modelo IA cargado exitosamente', 'success');
            agregarLineaConsola('INFO', `✅ Modelo IA ${data.modelo} cargado y listo.`);
        } else {
            mostrarToast('❌ Error al cargar modelo IA', 'error');
            agregarLineaConsola('CRITICAL', `Error IA: ${data.error}`);
        }
    } catch (e) {
        mostrarToast('Error de comunicación al cargar IA', 'error');
    }

    actualizarEstadoIA();
}

// ══════════════════════════════════════════════════════════════
// SISTEMA DE VOZ (Web Speech API - Español)
// ══════════════════════════════════════════════════════════════

const VortexVoz = {
    vozEspanol: null,
    habilitada: true,
    cola: [],
    hablando: false,

    /**
     * Inicializa el sistema de voz buscando una voz en español
     */
    inicializar() {
        if (!('speechSynthesis' in window)) {
            console.warn('[VORTEX VOZ] SpeechSynthesis no disponible en este navegador.');
            return;
        }

        const cargarVoces = () => {
            const voces = speechSynthesis.getVoices();
            // Buscar voz en español (preferir es-MX, luego es-ES, luego cualquier es-)
            this.vozEspanol = voces.find(v => v.lang === 'es-MX') ||
                              voces.find(v => v.lang === 'es-ES') ||
                              voces.find(v => v.lang.startsWith('es')) ||
                              voces.find(v => v.lang === 'es') ||
                              null;

            if (this.vozEspanol) {
                console.log(`[VORTEX VOZ] Voz seleccionada: ${this.vozEspanol.name} (${this.vozEspanol.lang})`);
            } else {
                console.warn('[VORTEX VOZ] No se encontró voz en español, se usará la voz por defecto.');
            }
        };

        // Las voces pueden cargarse de forma asíncrona
        if (speechSynthesis.getVoices().length > 0) {
            cargarVoces();
        }
        speechSynthesis.onvoiceschanged = cargarVoces;
    },

    /**
     * Habla un texto en español con limpieza previa
     */
    hablar(texto) {
        if (!this.habilitada || !texto || !('speechSynthesis' in window)) return;

        // Cancelar cualquier habla pendiente para respuesta inmediata
        speechSynthesis.cancel();

        const limpio = this._limpiarTexto(texto);
        const utterance = new SpeechSynthesisUtterance(limpio);
        
        utterance.lang = 'es-MX';
        utterance.rate = 1.05;
        utterance.pitch = 0.95;
        utterance.volume = 1.0;

        if (this.vozEspanol) {
            utterance.voice = this.vozEspanol;
        }

        speechSynthesis.speak(utterance);
    },

    cancelar() {
        speechSynthesis.cancel();
    },

    _limpiarTexto(texto) {
        return texto
            .replace(/<[^>]*>?/gm, '') // Quitar HTML
            .replace(/[\[\]]/g, ' ')   // Quitar corchetes
            .replace(/[\n\r]+/g, '. ') // Nuevas líneas a puntos
            .replace(/\s+/g, ' ')      // Espacios extra
            .substring(0, 4000);       // Límite de seguridad
    },

    /**
     * Alterna activar/desactivar voz
     */
    toggle() {
        this.habilitada = !this.habilitada;
        if (!this.habilitada) {
            speechSynthesis.cancel();
        } else {
            this.hablar('Sistema de voz activado.');
        }
        return this.habilitada;
    },

    // ── Eventos tácticos ──

    eventoInicioSistema() {
        this.hablar(
            'VORTEX Security Intelligence inicializado. ' +
            'Todos los sistemas operativos. ' +
            'Módulo de defensa activo. ' +
            'Esperando instrucciones del operador.'
        );
    },

    eventoInicioAnalisis(totalLogs) {
        this.hablar(
            `Iniciando análisis táctico de ${totalLogs} registros de seguridad. ` +
            'Activando motores de detección.'
        );
    },

    eventoDeteccionCritica(tipoAtaque, ip) {
        this.hablar(
            `¡Alerta crítica! Se ha detectado un ataque de tipo: ${tipoAtaque}. ` +
            `Origen: ${ip}. Nivel de amenaza elevado.`
        );
    },

    eventoResumenFinal(resumen) {
        const total = resumen.total_logs || 0;
        const amenazas = resumen.total_amenazas || 0;
        const nivel = resumen.nivel_riesgo || 'BAJO';
        const score = resumen.score_riesgo || 0;

        this.hablar(
            `Análisis completo. Se procesaron ${total} registros. ` +
            `Se identificaron ${amenazas} amenazas potenciales. ` +
            `Nivel de riesgo general: ${nivel}. ` +
            `Puntuación de riesgo: ${score} de 100. ` +
            (nivel === 'ALTO' ? 'Se recomienda acción inmediata.' : 'Sistema en monitoreo continuo.')
        );
    },

    eventoReporteGenerado() {
        this.hablar('Reporte de inteligencia generado exitosamente. Documento disponible para descarga.');
    },
};

// ══════════════════════════════════════════════════════════════
// INICIALIZACIÓN
// ══════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
    VortexVoz.inicializar();
    ejecutarBootSequence();
    inicializarIngesta();
    actualizarEstadoIA();

    // Configurar botones de voz en contenedores
    document.body.addEventListener('click', (e) => {
        const btn = e.target.closest('.btn-voice-panel');
        if (btn) {
            const targetId = btn.getAttribute('data-target');
            const target = document.getElementById(targetId);
            if (target) {
                const texto = target.innerText || target.textContent;
                VortexVoz.hablar(texto);
                mostrarToast('🔊 Leyendo sección...', 'info');
            }
        }
    });
});
