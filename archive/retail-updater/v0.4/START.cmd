@echo off
set PYTHONDONTWRITEBYTECODE=1
cd /d "%~dp0"
where py >nul 2>nul
if not errorlevel 1 (
 py -3 app.py
) else (
 python app.py
)
if errorlevel 1 (
 echo Could not start. Use existing Python 3.9+ 64-bit with tkinter. No pip install needed.
 pause
)
