@echo off
setlocal

cd /d "%~dp0"

set "BIN=mycodex-relay.exe"
set "CONFIG=%~1"
set "STATE=relay-state.db"
if "%CONFIG%"=="" (
  if exist "relay-config.local.json" (
    set "CONFIG=relay-config.local.json"
  ) else (
    set "CONFIG=relay-config.json"
  )
) else (
  set "STATE=%~n1.db"
)

if not exist "%BIN%" (
  echo %BIN% not found in %CD%.
  exit /b 1
)

echo Starting MyCodex Relay with %CONFIG%...
wscript.exe //B "%~dp0start-relay-silent.vbs" "%CONFIG%" "%STATE%"
if errorlevel 1 exit /b 1

echo MyCodex Relay started.
endlocal
exit /b 0
