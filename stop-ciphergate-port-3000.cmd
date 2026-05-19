@echo off
for /f "tokens=5" %%a in ('netstat -ano ^| findstr /R /C:":3000 .*LISTENING"') do (
  echo Stopping process on port 3000: %%a
  taskkill /PID %%a /F
)
echo Done.
pause
