@echo off
REM FortiLogPortal - install
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
pause
