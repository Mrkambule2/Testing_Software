@echo off
REM Double-click this on the USB drive. No installation needed (Python 3.9+ required).
cd /d "%~dp0"
python secure_scan.py
if errorlevel 1 (
    echo.
  echo Python was not found or the scan was cancelled.
    echo Make sure Python 3.9+ is installed and added to PATH, or run: py secure_scan.py
)
pause
