/**
 * ═══════════════════════════════════════════════════════════════
 * VORTEX Security Intelligence - Mapa "Ojo de Dios"
 * Mapa interactivo con Leaflet.js (modo oscuro cyberpunk)
 * Visualización de ataques en tiempo real con animaciones
 * ═══════════════════════════════════════════════════════════════
 */

let mapaVortex = null;
let capasAtaque = [];
let animacionInterval = null;
let servidorMarker = null;

// Coordenadas del servidor base (México)
const SERVIDOR_BASE = { lat: 19.4326, lng: -99.1332 };

/**
 * Inicializa el mapa Leaflet con tema oscuro
 */
function inicializarMapa() {
    if (mapaVortex) return;

    const mapContainer = document.getElementById('god-eye-map');
    if (!mapContainer) return;

    mapaVortex = L.map('god-eye-map', {
        center: [SERVIDOR_BASE.lat, SERVIDOR_BASE.lng],
        zoom: 2,
        minZoom: 2,
        maxZoom: 12,
        zoomControl: true,
        attributionControl: true,
    });

    // Tile layer oscuro (CartoDB Dark Matter)
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a> &copy; <a href="https://carto.com/">CARTO</a>',
        subdomains: 'abcd',
        maxZoom: 19,
    }).addTo(mapaVortex);

    // Forzar recálculo de tamaño (el contenedor pudo estar oculto al inicio)
    setTimeout(() => {
        mapaVortex.invalidateSize();
    }, 100);

    // Marcador del servidor base
    servidorMarker = L.circleMarker([SERVIDOR_BASE.lat, SERVIDOR_BASE.lng], {
        radius: 10,
        color: '#00ff9f',
        fillColor: '#00ff9f',
        fillOpacity: 0.8,
        weight: 2,
    }).addTo(mapaVortex);

    servidorMarker.bindPopup(`
        <div style="font-family:'Share Tech Mono',monospace;color:#00ff9f;">
            <b>🏠 SERVIDOR BASE</b><br>
            Ciudad de México, MX 🇲🇽<br>
            <small>Lat: ${SERVIDOR_BASE.lat}, Lng: ${SERVIDOR_BASE.lng}</small>
        </div>
    `);

    // Agregar pulso al servidor base
    agregarPulso(SERVIDOR_BASE.lat, SERVIDOR_BASE.lng, '#00ff9f');

    // Agregar efecto radar
    agregarRadar();
}

/**
 * Agrega efecto de pulso circular
 */
function agregarPulso(lat, lng, color) {
    if (!mapaVortex) return;

    const pulso = L.circleMarker([lat, lng], {
        radius: 15,
        color: color,
        fillColor: color,
        fillOpacity: 0.1,
        weight: 1,
        className: 'pulse-marker'
    }).addTo(mapaVortex);

    capasAtaque.push(pulso);

    // Animar pulso
    let radius = 15;
    let opacity = 0.3;
    const pulseAnim = setInterval(() => {
        radius += 0.5;
        opacity -= 0.005;
        if (opacity <= 0) {
            radius = 15;
            opacity = 0.3;
        }
        pulso.setRadius(radius);
        pulso.setStyle({ fillOpacity: opacity, opacity: opacity });
    }, 50);

    // Guardar referencia para limpieza
    pulso._animInterval = pulseAnim;
}

/**
 * Agrega efecto radar rotatorio en el servidor base
 */
function agregarRadar() {
    if (!mapaVortex) return;

    // Círculos concéntricos del radar
    const radii = [200000, 500000, 1000000]; // metros
    radii.forEach(r => {
        const circulo = L.circle([SERVIDOR_BASE.lat, SERVIDOR_BASE.lng], {
            radius: r,
            color: 'rgba(0, 255, 159, 0.1)',
            fillColor: 'transparent',
            weight: 1,
            dashArray: '4 6',
        }).addTo(mapaVortex);
        capasAtaque.push(circulo);
    });
}

/**
 * Actualiza el mapa con nuevos datos de geolocalización
 */
function actualizarMapa(geoData) {
    if (!mapaVortex) {
        inicializarMapa();
        setTimeout(() => actualizarMapa(geoData), 600);
        return;
    }

    // Asegurar que Leaflet tenga el tamaño correcto (con delay para render de CSS)
    setTimeout(() => {
        mapaVortex.invalidateSize();
    }, 100);

    // Limpiar capas anteriores (excepto servidor base)
    capasAtaque.forEach(capa => {
        if (capa._animInterval) clearInterval(capa._animInterval);
        mapaVortex.removeLayer(capa);
    });
    capasAtaque = [];

    if (animacionInterval) {
        clearInterval(animacionInterval);
        animacionInterval = null;
    }

    // Re-agregar radar
    agregarRadar();

    const puntos = geoData.puntos || [];
    
    // Si no hay puntos, volver al servidor base y salir
    if (!puntos.length) {
        mapaVortex.setView([SERVIDOR_BASE.lat, SERVIDOR_BASE.lng], 4, { animate: true });
        return;
    }

    // Colores según tipo
    const colorMap = {
        'rojo': '#ff3366',
        'amarillo': '#ffaa00',
        'azul': '#00d4ff',
    };

    // Agregar puntos con animación secuencial y preparar límites (bounds)
    const puntosCoords = [[SERVIDOR_BASE.lat, SERVIDOR_BASE.lng]];
    let index = 0;
    const intervalDelay = Math.max(100, 3000 / puntos.length);

    animacionInterval = setInterval(() => {
        if (index >= puntos.length) {
            clearInterval(animacionInterval);
            animacionInterval = null;
            
            // Ajustar vista para ver todos los ataques (fitBounds)
            const bounds = L.latLngBounds(puntosCoords);
            mapaVortex.fitBounds(bounds, {
                padding: [50, 50],
                maxZoom: 10,
                animate: true,
                duration: 1.5
            });
            return;
        }

        const punto = puntos[index];
        puntosCoords.push([punto.lat, punto.lng]);
        agregarPuntoAtaque(punto, colorMap);
        index++;
    }, intervalDelay);

    // Actualizar overlay
    document.getElementById('map-overlay').innerHTML = `
        🎯 SERVIDOR BASE: MÉXICO 🇲🇽<br>
        📡 Orígenes detectados: ${puntos.length}
    `;
}

/**
 * Agrega un punto de ataque al mapa con línea animada
 */
function agregarPuntoAtaque(punto, colorMap) {
    if (!mapaVortex) return;

    const color = colorMap[punto.color] || '#00d4ff';
    const origenLat = punto.lat;
    const origenLng = punto.lng;

    // ── Marcador en el origen ──
    const marcadorOrigen = L.circleMarker([origenLat, origenLng], {
        radius: Math.min(8, 3 + punto.count * 0.3),
        color: color,
        fillColor: color,
        fillOpacity: 0.7,
        weight: 1.5,
    }).addTo(mapaVortex);

    // Popup con información
    const tiposStr = (punto.tipos || []).join(', ') || 'N/A';
    const estadoStr = punto.baneada ? '🔴 BANEADA' : '🟢 ACTIVA';
    marcadorOrigen.bindPopup(`
        <div style="font-family:'Share Tech Mono',monospace;font-size:0.8rem;">
            <b style="color:${color};">⚠ ${punto.ip}</b><br>
            📍 ${punto.ciudad}, ${punto.pais} ${punto.codigo}<br>
            🎯 Score: <b>${punto.score}</b>/100<br>
            📊 Peticiones: ${punto.count}<br>
            🔍 Tipos: ${tiposStr}<br>
            ${estadoStr}
        </div>
    `);

    capasAtaque.push(marcadorOrigen);

    // ── Pulso en el punto de origen ──
    if (punto.score >= 50) {
        agregarPulso(origenLat, origenLng, color);
    }

    // ── Línea animada desde origen al servidor ──
    dibujarLineaAnimada(origenLat, origenLng, SERVIDOR_BASE.lat, SERVIDOR_BASE.lng, color, punto.score);

    // ── Efecto de impacto en el servidor ──
    if (punto.score >= 60) {
        setTimeout(() => {
            agregarImpacto(SERVIDOR_BASE.lat, SERVIDOR_BASE.lng, color);
        }, 1500);
    }
}

/**
 * Dibuja una línea curva animada entre dos puntos
 */
function dibujarLineaAnimada(lat1, lng1, lat2, lng2, color, score) {
    if (!mapaVortex) return;

    // Crear puntos para la curva (Great Circle approximation)
    const numPuntos = 50;
    const puntosCurva = [];

    for (let i = 0; i <= numPuntos; i++) {
        const t = i / numPuntos;
        const lat = lat1 + (lat2 - lat1) * t;
        const lng = lng1 + (lng2 - lng1) * t;

        // Agregar curvatura (arco)
        const distancia = Math.sqrt(Math.pow(lat2 - lat1, 2) + Math.pow(lng2 - lng1, 2));
        const alturaArco = distancia * 0.15;
        const curvatura = Math.sin(t * Math.PI) * alturaArco;

        // Offset perpendicular para curvatura
        const dx = lng2 - lng1;
        const dy = lat2 - lat1;
        const len = Math.sqrt(dx * dx + dy * dy);
        const nx = -dy / (len || 1);
        const ny = dx / (len || 1);

        puntosCurva.push([lat + nx * curvatura, lng + ny * curvatura]);
    }

    // Línea principal (trail)
    const linea = L.polyline(puntosCurva, {
        color: color,
        weight: score >= 70 ? 2 : 1.5,
        opacity: 0.5,
        dashArray: '8 4',
        className: 'attack-line'
    }).addTo(mapaVortex);

    capasAtaque.push(linea);

    // Partícula animada a lo largo de la línea
    animarParticula(puntosCurva, color);
}

/**
 * Anima una partícula a lo largo de una curva
 */
function animarParticula(puntos, color) {
    if (!mapaVortex || !puntos.length) return;

    let index = 0;
    const particula = L.circleMarker(puntos[0], {
        radius: 3,
        color: color,
        fillColor: '#ffffff',
        fillOpacity: 0.9,
        weight: 1,
    }).addTo(mapaVortex);

    capasAtaque.push(particula);

    const moverParticula = () => {
        index++;
        if (index >= puntos.length) {
            index = 0; // Loop
        }
        particula.setLatLng(puntos[index]);
    };

    const animInterval = setInterval(moverParticula, 60);
    particula._animInterval = animInterval;
}

/**
 * Agrega efecto de impacto (ondas expansivas) en un punto
 */
function agregarImpacto(lat, lng, color) {
    if (!mapaVortex) return;

    // Crear ondas expansivas
    for (let i = 0; i < 3; i++) {
        setTimeout(() => {
            let radius = 5;
            let opacity = 0.6;

            const onda = L.circleMarker([lat, lng], {
                radius: radius,
                color: color,
                fillColor: color,
                fillOpacity: opacity * 0.3,
                weight: 1.5,
            }).addTo(mapaVortex);

            capasAtaque.push(onda);

            const expand = setInterval(() => {
                radius += 1;
                opacity -= 0.015;

                if (opacity <= 0) {
                    clearInterval(expand);
                    if (mapaVortex.hasLayer(onda)) {
                        mapaVortex.removeLayer(onda);
                    }
                    return;
                }

                onda.setRadius(radius);
                onda.setStyle({
                    fillOpacity: opacity * 0.3,
                    opacity: opacity
                });
            }, 40);

            onda._animInterval = expand;
        }, i * 300);
    }
}
