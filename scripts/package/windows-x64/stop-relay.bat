@echo off
setlocal

echo Stopping mycodex-relay.exe...
taskkill /f /t /im mycodex-relay.exe >nul 2>&1
echo Done.

endlocal
exit /b 0
