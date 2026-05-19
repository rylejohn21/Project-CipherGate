@echo off
cd /d "%~dp0"
netstat -ano | findstr /R /C:":3000 .*LISTENING" >nul
if %errorlevel%==0 (
  echo CipherGate or another app is already running on port 3000.
  echo Opening http://localhost:3000/login.html
  start "" "http://localhost:3000/login.html"
  echo.
  echo If the page is wrong or broken, close the old Node window first.
  pause
  exit /b 0
)

echo Starting CipherGate on http://localhost:3000
echo.
npm.cmd start
pause
