@echo off
REM Radar Marista - update
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0update.ps1" %*
pause
