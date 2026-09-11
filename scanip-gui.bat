@echo off
REM Windows: Doppelklick startet die grafische Oberflaeche.
cd /d "%~dp0"
where pythonw >nul 2>nul && (start "" pythonw -m scanip --gui & exit /b)
where python  >nul 2>nul && (python -m scanip --gui & exit /b)
echo Python 3 wurde nicht gefunden. Bitte von python.org installieren
echo und bei der Installation "Add Python to PATH" ankreuzen.
pause
