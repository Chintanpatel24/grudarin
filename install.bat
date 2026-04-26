@echo off
REM ================================================================
REM                     G R U D A R I N
REM               Installer for Windows
REM ================================================================
REM
REM Usage: Right-click and "Run as Administrator"
REM        or run from an Admin command prompt:
REM          install.bat
REM
REM ================================================================

setlocal enabledelayedexpansion

echo.
echo     ================================================================
echo                           G R U D A R I N
echo                     Windows Installer v2.0.0
echo     ================================================================
echo.

REM Check admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo   [warn] Not running as Administrator.
    echo   [warn] Some steps may fail. Right-click and Run as Admin.
    echo.
)

REM ----------------------------------------------------------------
REM Step 1: Check Python
REM ----------------------------------------------------------------
echo   [step] Checking Python...
python --version >nul 2>&1
if %errorLevel% neq 0 (
    python3 --version >nul 2>&1
    if %errorLevel% neq 0 (
        echo   [fail] Python not found.
        echo   [info] Download from: https://www.python.org/downloads/
        echo   [info] Make sure to check "Add Python to PATH" during install.
        pause
        exit /b 1
    )
    set PYTHON=python3
) else (
    set PYTHON=python
)
echo   [ok]   Python found
for /f "tokens=*" %%i in ('%PYTHON% --version 2^>^&1') do echo          %%i

REM ----------------------------------------------------------------
REM Step 2: Check pip
REM ----------------------------------------------------------------
echo   [step] Checking pip...
%PYTHON% -m pip --version >nul 2>&1
if %errorLevel% neq 0 (
    echo   [warn] pip not found. Attempting to install...
    %PYTHON% -m ensurepip --upgrade >nul 2>&1
)
echo   [ok]   pip available

REM ----------------------------------------------------------------
REM Step 3: Install Python dependencies
REM ----------------------------------------------------------------
echo   [step] Installing Python dependencies...
%PYTHON% -m pip install --upgrade pip --quiet 2>nul
%PYTHON% -m pip install scapy pygame --quiet 2>nul
if %errorLevel% neq 0 (
    echo   [warn] Some packages may have failed. Trying individually...
    %PYTHON% -m pip install scapy --quiet 2>nul
    %PYTHON% -m pip install pygame --quiet 2>nul
)
echo   [ok]   Python packages installed

REM ----------------------------------------------------------------
REM Step 4: Check for C++ compiler (MSVC or MinGW)
REM ----------------------------------------------------------------
echo   [step] Checking C++ compiler...
where cl >nul 2>&1
if %errorLevel% equ 0 (
    echo   [ok]   MSVC compiler found
    set CXX=cl
    goto :compile_scanner
)

where g++ >nul 2>&1
if %errorLevel% equ 0 (
    echo   [ok]   MinGW g++ found
    set CXX=g++
    goto :compile_scanner
)

echo   [warn] No C++ compiler found. Scanner will use Python fallback.
echo   [info] Install MinGW or Visual Studio Build Tools for C++ scanner.
goto :skip_compile

:compile_scanner
echo   [step] Compiling C++ port scanner...
if not exist "bin" mkdir bin
if "%CXX%"=="g++" (
    g++ -std=c++17 -O2 -Wall -o bin\grudarin_scanner.exe scanner\scanner.cpp -lws2_32 2>nul
) else (
    cl /EHsc /O2 /Fe:bin\grudarin_scanner.exe scanner\scanner.cpp ws2_32.lib 2>nul
)
if exist "bin\grudarin_scanner.exe" (
    echo   [ok]   Scanner compiled: bin\grudarin_scanner.exe
) else (
    echo   [warn] Compilation failed. Using Python fallback.
)

:skip_compile

REM ----------------------------------------------------------------
REM Step 5: Check for Go compiler
REM ----------------------------------------------------------------
echo   [step] Checking Go compiler...
where go >nul 2>&1
if %errorLevel% equ 0 (
    echo   [ok]   Go found
    echo   [step] Building Go network probe...
    if not exist "bin" mkdir bin
    cd netprobe
    go build -o ..\bin\grudarin_netprobe.exe netprobe.go 2>nul
    cd ..
    if exist "bin\grudarin_netprobe.exe" (
        echo   [ok]   Netprobe compiled: bin\grudarin_netprobe.exe
    ) else (
        echo   [warn] Go build failed. Using Python fallback.
    )
) else (
    echo   [warn] Go not found. Netprobe will use Python fallback.
)

REM ----------------------------------------------------------------
REM Step 6: Check Npcap/WinPcap
REM ----------------------------------------------------------------
echo   [step] Checking packet capture driver...
if exist "C:\Windows\System32\Npcap" (
    echo   [ok]   Npcap found
) else if exist "C:\Windows\System32\wpcap.dll" (
    echo   [ok]   WinPcap found
) else (
    echo   [warn] No packet capture driver found.
    echo   [info] Install Npcap from: https://nmap.org/npcap/
    echo   [info] Check "WinPcap API-compatible Mode" during Npcap install.
)

REM ----------------------------------------------------------------
REM Step 7: Create launcher batch file
REM ----------------------------------------------------------------
echo   [step] Creating launcher...
(
echo @echo off
echo cd /d "%~dp0"
echo %PYTHON% -m grudarin %%*
) > grudarin.bat
echo   [ok]   Launcher created: grudarin.bat

REM ----------------------------------------------------------------
REM Step 8: Install package
REM ----------------------------------------------------------------
echo   [step] Installing Grudarin package...
%PYTHON% -m pip install -e . --quiet 2>nul
echo   [ok]   Package registered

REM ----------------------------------------------------------------
REM Verify
REM ----------------------------------------------------------------
echo.
echo   ================================================================
echo     Installation complete.
echo   ================================================================
echo.
echo   Usage:
echo     grudarin.bat --list
echo     grudarin.bat --scan "Wi-Fi"
echo     grudarin.bat --scan "Ethernet" -o C:\reports
echo     grudarin.bat --help
echo.
echo   Note: Run as Administrator for packet capture.
echo.
pause
