@echo off
setlocal

set "ROOT=%~dp0"
set "VERSION=%~1"
if "%VERSION%"=="" set "VERSION=dev"

powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%scripts\build.ps1" -Version "%VERSION%"
exit /b %ERRORLEVEL%
