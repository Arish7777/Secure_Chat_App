@echo off
echo ===========================================
echo       Secure Chat Application Setup
echo ===========================================
echo.

:: Get the local IP address
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /R /C:"IPv4 Address"') do (
    set IP=%%a
    goto :found
)
:found
set IP=%IP:~1%

echo Starting servers...
echo.

:: Start the chat server in a new window
start cmd /k "python server.py"

:: Wait a moment for the chat server to start
timeout /t 2

:: Start the Flask app
start cmd /k "python app.py"

echo.
echo ===========================================
echo         Access URLs:
echo ===========================================
echo Local Access:    http://localhost:8000
echo Network Access:  http://%IP%:8000
echo.
echo To access from other devices:
echo 1. Make sure they are on the same network
echo 2. Open any browser
echo 3. Enter the Network Access URL above
echo.
echo Press any key to close this window...
pause > nul 