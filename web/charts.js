/**
 * ═══════════════════════════════════════════════════════════════
 * VORTEX Security Intelligence - Gráficas (Chart.js)
 * Visualización de datos del análisis de seguridad
 * ═══════════════════════════════════════════════════════════════
 */

// Paleta de colores VORTEX
const COLORES_VORTEX = [
    '#00ff9f', '#00d4ff', '#ff3366', '#ffaa00', '#a855f7',
    '#22d3ee', '#f472b6', '#34d399', '#fbbf24', '#818cf8',
    '#fb923c', '#4ade80', '#f87171', '#38bdf8', '#c084fc',
];

const COLORES_VORTEX_BG = COLORES_VORTEX.map(c => c + '33');

// Configuración global de Chart.js
Chart.defaults.color = '#8892a0';
Chart.defaults.borderColor = 'rgba(26, 26, 62, 0.5)';
Chart.defaults.font.family = "'Share Tech Mono', 'Consolas', monospace";
Chart.defaults.font.size = 11;

// Instancias de charts (para destruir y recrear)
let chartInstances = {};

/**
 * Renderiza todas las gráficas del dashboard
 */
function renderizarGraficas(datos) {
    renderizarChartTiposAtaque(datos.tipos_ataque || []);
    renderizarChartTimeline(datos.timeline || []);
    renderizarChartOS(datos.os_data || []);
    renderizarChartBrowsers(datos.browsers_data || []);
}

/**
 * Destruye un chart existente antes de recrearlo
 */
function destruirChart(id) {
    if (chartInstances[id]) {
        chartInstances[id].destroy();
        delete chartInstances[id];
    }
}

/**
 * Gráfica: Ataques por Tipo (Doughnut)
 */
function renderizarChartTiposAtaque(tipos) {
    destruirChart('attack-types');

    const ctx = document.getElementById('chart-attack-types');
    if (!ctx || !tipos.length) return;

    const labels = tipos.map(t => t.tipo);
    const values = tipos.map(t => t.count);

    chartInstances['attack-types'] = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: COLORES_VORTEX_BG.slice(0, labels.length),
                borderColor: COLORES_VORTEX.slice(0, labels.length),
                borderWidth: 1.5,
                hoverBorderWidth: 2,
                hoverOffset: 8,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            cutout: '55%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 12,
                        usePointStyle: true,
                        pointStyle: 'rectRounded',
                        font: { size: 10 }
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(10, 10, 30, 0.95)',
                    borderColor: '#00ff9f',
                    borderWidth: 1,
                    titleFont: { family: "'Orbitron', sans-serif", size: 11 },
                    bodyFont: { family: "'Share Tech Mono', monospace", size: 11 },
                    padding: 12,
                    callbacks: {
                        label: function(context) {
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const pct = ((context.parsed / total) * 100).toFixed(1);
                            return ` ${context.label}: ${context.parsed} (${pct}%)`;
                        }
                    }
                }
            },
            animation: {
                animateRotate: true,
                duration: 1200,
            }
        }
    });
}

/**
 * Gráfica: Timeline de Eventos (Line)
 */
function renderizarChartTimeline(timeline) {
    destruirChart('timeline');

    const ctx = document.getElementById('chart-timeline');
    if (!ctx || !timeline.length) return;

    const labels = timeline.map(t => {
        const parts = t.hora.split(' ');
        return parts.length > 1 ? parts[1] + ':00' : t.hora;
    });

    const datasets = [
        {
            label: 'Crítico',
            data: timeline.map(t => t.CRITICAL || 0),
            borderColor: '#ff3366',
            backgroundColor: 'rgba(255, 51, 102, 0.4)',
            fill: true,
            tension: 0.4,
            borderWidth: 2,
            pointRadius: 2
        },
        {
            label: 'Alto',
            data: timeline.map(t => t.HIGH || 0),
            borderColor: '#fb923c',
            backgroundColor: 'rgba(251, 146, 60, 0.3)',
            fill: true,
            tension: 0.4,
            borderWidth: 2,
            pointRadius: 2
        },
        {
            label: 'Medio',
            data: timeline.map(t => t.MEDIUM || 0),
            borderColor: '#fbbf24',
            backgroundColor: 'rgba(251, 191, 36, 0.2)',
            fill: true,
            tension: 0.4,
            borderWidth: 2,
            pointRadius: 2
        },
        {
            label: 'Bajo/Info',
            data: timeline.map(t => t.LOW || 0),
            borderColor: '#00ff9f',
            backgroundColor: 'rgba(0, 255, 159, 0.1)',
            fill: true,
            tension: 0.4,
            borderWidth: 2,
            pointRadius: 2
        }
    ];

    chartInstances['timeline'] = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: datasets
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            interaction: {
                mode: 'index',
                intersect: false,
            },
            scales: {
                x: {
                    grid: { color: 'rgba(26, 26, 62, 0.3)' },
                    ticks: { maxRotation: 45, font: { size: 9 } }
                },
                y: {
                    stacked: true,
                    beginAtZero: true,
                    grid: { color: 'rgba(26, 26, 62, 0.3)' },
                    ticks: { precision: 0, font: { size: 10 } }
                }
            },
            plugins: {
                legend: {
                    display: true,
                    position: 'top',
                    labels: { boxWidth: 10, font: { size: 9 }, usePointStyle: true }
                },
                tooltip: {
                    backgroundColor: 'rgba(10, 10, 30, 0.95)',
                    borderColor: '#00ff9f',
                    borderWidth: 1,
                    padding: 10,
                    callbacks: {
                        footer: (items) => {
                            const total = items.reduce((a, b) => a + b.parsed.y, 0);
                            return `Total: ${total} eventos`;
                        }
                    }
                },
                zoom: {
                    pan: {
                        enabled: true,
                        mode: 'x',
                        modifierKey: 'alt', // Alt + Drag para pan
                    },
                    zoom: {
                        wheel: { enabled: true },
                        pinch: { enabled: true },
                        mode: 'x',
                    }
                }
            },
            onClick: (e, elements) => {
                if (elements.length > 0) {
                    const idx = elements[0].index;
                    const data = timeline[idx];
                    mostrarToast(`Detalle ${data.hora}: ${data.CRITICAL} Críticos, ${data.HIGH} Altos`, 'info');
                } else if (e.native.detail === 2) {
                    // Doble clic para resetear zoom
                    chartInstances['timeline'].resetZoom();
                }
            },
            animation: { duration: 1500 }
        }
    });
}

/**
 * Gráfica: Sistemas Operativos (Pie)
 */
function renderizarChartOS(osData) {
    destruirChart('os');

    const ctx = document.getElementById('chart-os');
    if (!ctx || !osData.length) return;

    const labels = osData.map(o => o.os);
    const values = osData.map(o => o.count);

    chartInstances['os'] = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: COLORES_VORTEX_BG.slice(0, labels.length),
                borderColor: COLORES_VORTEX.slice(0, labels.length),
                borderWidth: 1.5,
                hoverOffset: 6,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 10,
                        usePointStyle: true,
                        font: { size: 10 }
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(10, 10, 30, 0.95)',
                    borderColor: '#00d4ff',
                    borderWidth: 1,
                    padding: 10,
                }
            },
            animation: { duration: 1000 }
        }
    });
}

/**
 * Gráfica: Navegadores / Clientes (Bar horizontal)
 */
function renderizarChartBrowsers(browsersData) {
    destruirChart('browsers');

    const ctx = document.getElementById('chart-browsers');
    if (!ctx || !browsersData.length) return;

    const labels = browsersData.map(b => b.browser);
    const values = browsersData.map(b => b.count);

    chartInstances['browsers'] = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Peticiones',
                data: values,
                backgroundColor: COLORES_VORTEX_BG.slice(0, labels.length),
                borderColor: COLORES_VORTEX.slice(0, labels.length),
                borderWidth: 1,
                borderRadius: 4,
                maxBarThickness: 30,
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: true,
            scales: {
                x: {
                    beginAtZero: true,
                    grid: { color: 'rgba(26, 26, 62, 0.3)' },
                    ticks: { precision: 0, font: { size: 10 } }
                },
                y: {
                    grid: { display: false },
                    ticks: { font: { size: 10 } }
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: 'rgba(10, 10, 30, 0.95)',
                    borderColor: '#00d4ff',
                    borderWidth: 1,
                    padding: 10,
                }
            },
            animation: { duration: 1200 }
        }
    });
}
