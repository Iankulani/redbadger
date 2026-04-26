@echo off
:: RedBadger Security Platform - Windows Installation Script
:: Requires: Python 3.7+ and Administrator privileges

setlocal enabledelayedexpansion

:: Configuration
set INSTALL_DIR=%USERPROFILE%\RedBadger
set DATA_DIR=%APPDATA%\RedBadger
set LOG_DIR=%TEMP%\RedBadger

:: Colors for output (using ANSI escape codes)
set "GREEN=[92m"
set "RED=[91m"
set "YELLOW=[93m"
set "BLUE=[94m"
set "RESET=[0m"

echo %GREEN%========================================%RESET%
echo %GREEN%RedBadger Security Platform Installer%RESET%
echo %GREEN%========================================%RESET%
echo.

:: Check for Administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo %RED%[ERROR] This script requires Administrator privileges!%RESET%
    echo Please right-click and select "Run as Administrator"
    pause
    exit /b 1
)

:: Check Python installation
echo %BLUE%[INFO] Checking Python installation...%RESET%
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo %RED%[ERROR] Python 3.7+ is not installed!%RESET%
    echo Please install Python from https://python.org
    pause
    exit /b 1
)

:: Check Python version
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo %GREEN%[OK] Python %PYTHON_VERSION% found%RESET%

:: Create directories
echo %BLUE%[INFO] Creating directories...%RESET%
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"
echo %GREEN%[OK] Directories created%RESET%

:: Install Python packages
echo %BLUE%[INFO] Installing Python dependencies...%RESET%
pip install --upgrade pip
pip install requests psutil flask discord.py python-telegram-bot slack-sdk python-whois dnspython cryptography
if %errorLevel% equ 0 (
    echo %GREEN%[OK] Dependencies installed%RESET%
) else (
    echo %YELLOW%[WARNING] Some optional dependencies may have failed%RESET%
)

:: Copy application files
echo %BLUE%[INFO] Copying application files...%RESET%
copy "%~dp0redbadger.py" "%INSTALL_DIR%\"
if exist "%~dp0requirements.txt" copy "%~dp0requirements.txt" "%INSTALL_DIR%\"
echo %GREEN%[OK] Files copied%RESET%

:: Create configuration file
echo %BLUE%[INFO] Creating configuration...%RESET%
(
echo {
echo     "database": "%DATA_DIR%\\redbadger.db",
echo     "log_file": "%LOG_DIR%\\redbadger.log",
echo     "report_dir": "%DATA_DIR%\\reports",
echo     "web_port": 5000,
echo     "web_host": "0.0.0.0",
echo     "monitoring_enabled": true
echo }
) > "%INSTALL_DIR%\\config.json"
echo %GREEN%[OK] Configuration created%RESET%

:: Create startup script
echo %BLUE%[INFO] Creating startup script...%RESET%
(
echo @echo off
echo cd /d "%INSTALL_DIR%"
echo python redbadger.py
echo pause
) > "%INSTALL_DIR%\\start_redbadger.bat"
echo %GREEN%[OK] Startup script created%RESET%

:: Create firewall rule (optional)
echo %BLUE%[INFO] Configuring Windows Firewall...%RESET%
netsh advfirewall firewall add rule name="RedBadger Web" dir=in action=allow protocol=TCP localport=5000 >nul 2>&1
netsh advfirewall firewall add rule name="RedBadger Phish" dir=in action=allow protocol=TCP localport=8080 >nul 2>&1
echo %GREEN%[OK] Firewall rules added%RESET%

:: Create shortcut
echo %BLUE%[INFO] Creating desktop shortcut...%RESET%
powershell -Command "$WS = New-Object -ComObject WScript.Shell; $SC = $WS.CreateShortcut('%USERPROFILE%\Desktop\RedBadger.lnk'); $SC.TargetPath = '%INSTALL_DIR%\start_redbadger.bat'; $SC.Save()"
echo %GREEN%[OK] Desktop shortcut created%RESET%

:: Installation complete
echo.
echo %GREEN%========================================%RESET%
echo %GREEN%Installation Complete!%RESET%
echo %GREEN%========================================%RESET%
echo.
echo %BLUE%📍 Installation Directory: %INSTALL_DIR%%RESET%
echo %BLUE%📍 Data Directory: %DATA_DIR%%RESET%
echo %BLUE%📍 Log Directory: %LOG_DIR%%RESET%
echo.
echo %YELLOW%🚀 To start RedBadger:%RESET%
echo    Double-click: %INSTALL_DIR%\start_redbadger.bat
echo    OR Desktop shortcut: RedBadger.lnk
echo.
echo %YELLOW%🌐 Web Interface:%RESET%
echo    http://localhost:5000
echo.
echo %YELLOW%⚠️  IMPORTANT: Configure Discord/Telegram/Slack on first run!%RESET%
echo.
pause