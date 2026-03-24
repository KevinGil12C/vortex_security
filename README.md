# 🌌 VORTEX Security Intelligence
### ⚡ Tactical Analysis Core v1.0 // SIEM & IDS con IA Neural Local

![License](https://img.shields.io/badge/License-MIT-green.svg)
![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![AI](https://img.shields.io/badge/IA-Local-purple.svg)
![Eel](https://img.shields.io/badge/Framework-Eel-orange.svg)
![Cyberpunk](https://img.shields.io/badge/Aesthetic-Tactical_Cyberpunk-red.svg)

**VORTEX** es una suite de inteligencia de ciberseguridad avanzada diseñada para recolectar, procesar y visualizar logs de seguridad (SIEM) mediante el uso de **Inteligencia Artificial Local**. A diferencia de otras herramientas, VORTEX no requiere conexión a internet para analizar amenazas complejas, garantizando que tus datos estratégicos nunca abandonen tu máquina.

---

## 🛰️ ¿Por qué VORTEX? (Filosofía del Proyecto)

En el panorama actual de la ciberseguridad, la privacidad y la velocidad de respuesta son críticas. VORTEX nace para solucionar tres problemas principales:
1. **Privacidad de Datos**: Los analistas suelen temer enviar logs sensibles a APIs externas (OpenAI, etc.). VORTEX usa modelos de lenguaje (LLMs) que corren localmente.
2. **Fatiga de Alertas**: Filtra el "ruido" de los logs comunes para centrarse en vectores de ataque reales como SQLi, XSS y Brute Force.
3. **Accesibilidad Táctica**: Un dashboard interactivo con mapas, voz y gráficas de alto rendimiento que permite a cualquier operador entender el estado de seguridad de un vistazo.

---

## ✨ Características Técnicas Detalladas

### 🧠 1. Núcleo Neural IA (Local LLM)
Utiliza modelos optimizados como **Qwen-0.5B** o **TinyLlama** para procesar los datos analizados.
- **Generación de Informes**: Traduce miles de líneas de logs técnicos a un informe ejecutivo en español profesional.
- **Recomendaciones Tácticas**: La IA sugiere pasos específicos de mitigación basados en las amenazas detectadas.

### 🔊 2. Interfaz de Audio Interactiva (VortexVoz)
Sistema de síntesis de voz (`SpeechSynthesis`) integrado en cada contenedor del dashboard.
- **Lectura Selectiva**: Puedes pulsar el icono 🔊 en cualquier panel para que el sistema te lea el contenido de esa sección.
- **Alertas Críticas**: El sistema te avisará verbalmente si detecta un ataque de alta severidad durante el escaneo.

### 🌍 3. Ojo de Dios (Geolocalización Determinista)
Visualización en un mapa interactivo (Leaflet) de los orígenes de los ataques.
- **Motor Offline**: Utiliza una base de datos local para geolocalizar IPs instantáneamente sin depender de APIs externas lentas.
- **Auto-Focus**: El mapa se centra y ajusta automáticamente para mostrar todos los puntos de ataque detectados.

### 📈 4. Timeline de Eventos de Alta Resolución
- **Gráfica Apilada**: Visualiza hilos de eventos por severidad (Crítico, Alto, Medio, Bajo).
- **Control de Zoom**: Utiliza la rueda del ratón para hacer zoom en franjas horarias específicas (como en el inspector de red de Chrome).
- **Paneo**: Mantén `Alt` + arrastrar para navegar por el historial.

---

## ⚡ Ejecución Rápida (Windows - Recomendado)

VORTEX incluye scripts de automatización para que no tengas que lidiar con la consola si no lo deseas:

1. **`start.bat`**: 
   - Crea/Activa automáticamente el entorno virtual (`venv`).
   - Verifica e instala las dependencias necesarias.
   - Configura la codificación UTF-8 de la consola para que veas el arte ASCII correctamente.
   - Inicia el servidor `main.py` y abre el navegador por defecto.
2. **`stop.bat`**: 
   - Finaliza de forma segura todos los procesos de Python y la interfaz web.

---

## 🛠️ Instrucciones de Uso (Operación del Dashboard)

Una vez iniciado el sistema con `start.bat`, sigue estos pasos para realizar un análisis:

1. **Ingesta de Datos**: Puedes arrastrar un archivo de log directamente a la zona de "Arrastrar Log" en la interfaz o dejar que el sistema lea el archivo por defecto configurado en el `.env`.
2. **Exploración del Mapa**: Verifica en el **"Ojo de Dios"** la procedencia geográfica de las amenazas. Utiliza el zoom para identificar clústeres de IPs atacantes.
3. **Análisis de Timeline**: Observa el gráfico de eventos. Si ves un pico rojo, usa el scroll del ratón para hacer zoom en esa hora y entender cuándo ocurrió el ataque.
4. **Generación de Reporte IA**: Pulsa el botón **"Generar Informe IA"**. El sistema procesará los datos localmente y te entregará un resumen ejecutivo detallado.
5. **Lectura Asistida**: Si estás realizando otras tareas, pulsa el botón 🔊 en el panel de resultados para que VORTEX te lea el resumen del análisis.
6. **Exportación**: Genera un **PDF** profesional con todos los hallazgos para compartir con el equipo de respuesta a incidentes.

---

## 🛠️ Tecnologías y Librerías de Python (Detalle Técnico)

El corazón de VORTEX está construido con un ecosistema robusto de librerías de alto rendimiento:

- **🐍 Eel**: El puente fundamental. Permite conectar la potencia de Python para el procesamiento de datos con la flexibilidad de HTML/JS/CSS para la interfaz de usuario.
- **🤖 Transformers + Torch**: El motor neural. Usamos la API de **Hugging Face** para cargar y ejecutar modelos de lenguaje (LLM) de forma local. No enviamos datos al exterior; todo ocurre en tu CPU/GPU.
- **📊 Scikit-Learn + NumPy**: El cerebro analítico. Estas librerías permiten realizar el **Clustering de IPs** y la **Detección de Anomalías** mediante modelos de Machine Learning estadístico.
- **📄 ReportLab**: El generador táctico. Se encarga de transformar los hallazgos de seguridad en documentos **PDF profesionales** y legibles.
- **🔊 PyTTSx3**: El módulo de audio. Proporciona una interfaz de voz nativa para alertas y lecturas en tiempo real.
- **⚙️ Python-Dotenv**: Gestión de configuración. Facilita la personalización del sistema (modelos, rutas, voz) mediante archivos de entorno `.env`.
- **⚡ Accelerate**: Optimización de carga. Permite que los modelos de IA se carguen de forma eficiente en máquinas con recursos limitados.

---

## 🚀 Instalación Manual (Paso a Paso)

### Requisitos Previos
- Python 3.10 o superior instalado.
- Google Chrome o Microsoft Edge (para la interfaz Eel).

1. **Clonación del Sistema:**
   ```bash
   git clone https://github.com/KevinGil12C/vortex_security.git
   cd vortex_security
   ```

2. **Entorno y Dependencias:**
   ```bash
   python -m venv venv
   venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Configuración del Modelo IA:**
   VORTEX descargará el modelo automáticamente la primera vez. Se recomienda tener al menos 8GB de RAM (4GB de RAM de Vídeo si usas GPU).
   Configura tu `.env`:
   ```env
   VOICE_ENABLED=True
   MODEL_NAME=Qwen/Qwen1.5-0.5B-Chat
   LOG_PATH=writable/logs/security_audit.log
   ```

---

## 🛡️ Arquitectura del Software

- **Motor de Reglas**: Parser con RegEx avanzado para detección estática (Dossier de amenazas).
- **Pre-Procesador**: Limpieza de datos y normalización de severidades.
- **Núcleo Neural**: Motor de inferencia Transformers encargado del análisis cualitativo.
- **Frontend Táctico**: UI Cyberpunk construida en Vanilla CSS y JavaScript para máximo rendimiento.

---

## 📜 Créditos y Licencia

Desarrollado por **KevinGil12C**. 
Este proyecto es de código abierto bajo la licencia MIT.

> **Nota de Seguridad**: VORTEX es una herramienta de monitoreo y análisis. No debe usarse para fines maliciosos. El desarrollador no se hace responsable del uso inadecuado del sistema.

---
*VORTEX Intelligence - Versión Procesada por Núcleo Neural v1.0*