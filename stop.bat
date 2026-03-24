@echo off

title VORTEX Security Intelligence - Cerrando...
echo ********************************************************
echo *  VORTEX Security Intelligence                       *
echo *  Deteniendo sistema...                              *
echo ********************************************************
echo.

echo [+] Buscando procesos VORTEX...
taskkill /F /IM "python.exe" /FI "WINDOWTITLE eq VORTEX*" 2>nul
taskkill /F /FI "WINDOWTITLE eq VORTEX*" 2>nul

REM Matar procesos Python en el puerto 8147
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :8147 2^>nul') do (
    echo [+] Cerrando proceso PID: %%a
    taskkill /F /PID %%a 2>nul
)

echo.
echo [+] VORTEX Security Intelligence detenido.
echo.
timeout /t 3
