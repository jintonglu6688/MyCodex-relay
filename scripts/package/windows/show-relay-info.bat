@echo off
setlocal

cd /d "%~dp0"

set "BIN=mycodex-relay.exe"
set "CONFIG=%~1"
if "%CONFIG%"=="" (
  if exist "relay-config.local.json" (
    set "CONFIG=relay-config.local.json"
  ) else (
    set "CONFIG=relay-config.json"
  )
)

if not exist "%BIN%" (
  echo %BIN% not found in %CD%.
  pause
  exit /b 1
)

if not exist "%CONFIG%" (
  echo %CONFIG% not found. Creating default config...
  "%BIN%" configure --config "%CONFIG%" --state relay-state.db
  if errorlevel 1 (
    pause
    exit /b 1
  )
  echo.
)

"%BIN%" info --config "%CONFIG%" --ensure-tenant --tenant-name Local
echo.
pause
endlocal
exit /b 0
