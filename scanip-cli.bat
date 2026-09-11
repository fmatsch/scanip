@echo off
REM Windows: oeffnet eine Eingabeaufforderung im Projektordner.
cd /d "%~dp0"
python -m scanip %*
if "%~1"=="" pause
