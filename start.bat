@echo off
setlocal enabledelayedexpansion

title SentinelDICOM VeilGuard - Startup Launcher

echo ======================================================================
echo   SentinelDICOM VeilGuard - Medical Cybersecurity Command Center
echo ======================================================================
echo.

:: 1. Check if Python is available in PATH
where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python was not found in your system PATH!
    echo Please install Python 3.10 or newer and make sure "Add Python to PATH" is checked.
    echo.
    pause
    exit /b 1
)

:: 2. Verify if required dependencies are already installed
echo [1/3] Checking Python dependencies...
python -c "import fastapi, uvicorn, pydicom, PIL, numpy, multipart" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [OK] All required libraries are already installed!
) else (
    echo [INFO] Missing dependencies detected.
    echo [INFO] Installing required libraries from required.txt...
    python -m pip install -r "%~dp0required.txt"
    if !ERRORLEVEL! NEQ 0 (
        echo.
        echo [ERROR] Failed to install required packages!
        echo Please check your internet connection and try running:
        echo   python -m pip install -r required.txt
        echo.
        pause
        exit /b 1
    )
    echo [OK] All dependencies successfully installed!
)

:: 3. Display application link
echo.
echo ======================================================================
echo   BACKEND AND COMMAND CENTER READY
echo ======================================================================
echo   Web App Link:   http://localhost:8000/index.html
echo   Swagger API:    http://localhost:8000/docs
echo ======================================================================
echo.

:: 4. Launch web browser in background after 2 seconds
echo [2/3] Preparing to open web browser...
start "" /b cmd /c "timeout /t 2 /nobreak >nul && start http://localhost:8000/index.html"

:: 5. Start the backend server
echo [3/3] Starting VeilGuard backend engine on port 8000...
echo (Press CTRL + C at any time to shutdown the server)
echo.
python "%~dp0backend.py"

pause
