@echo off

title VORTEX Security Intelligence - Iniciando...
echo ********************************************************
echo *  VORTEX Security Intelligence                       *
echo *  Tactical Analysis Core                             *
echo ********************************************************
echo.

REM Verificar si existe entorno virtual
if not exist "venv" (
    echo [+] Creando entorno virtual...
    py -m venv venv
    echo [+] Entorno virtual creado.
    echo.
)

REM Activar entorno virtual
echo [+] Activando entorno virtual...
call venv\Scripts\activate.bat

REM Instalar dependencias
echo [+] Verificando dependencias...
py -m pip install -r requirements.txt --quiet
echo [+] Dependencias verificadas.
echo.

REM Iniciar aplicación
echo [+] Iniciando VORTEX Security Intelligence...
echo [+] Se abrira el navegador automaticamente.
echo [+] Para cerrar: Ctrl+C o ejecuta stop.bat
echo.
py main.py

pause
