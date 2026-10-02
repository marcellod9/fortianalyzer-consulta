@echo off
REM FortiLogPortal - update
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0update.ps1" %*
pause
