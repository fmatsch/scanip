@echo off
REM Windows: Doppelklick startet die Browser-Oberflaeche.
cd /d "%~dp0"
where python >nul 2>nul && (python -m scanip --web & exit /b)
echo Python 3 wurde nicht gefunden. Bitte von python.org installieren
echo und bei der Installation "Add Python to PATH" ankreuzen.
pause
