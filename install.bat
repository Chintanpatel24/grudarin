@echo off
setlocal

echo [1/5] Creating virtual environment
if not exist .venv (
    py -3 -m venv .venv 2>nul || python -m venv .venv
)
if errorlevel 1 (
    echo Failed to create the virtual environment.
    exit /b 1
)

echo [2/5] Activating environment
call .venv\Scripts\activate.bat
if errorlevel 1 (
    echo Failed to activate the virtual environment.
    exit /b 1
)

echo [3/5] Upgrading pip
python -m pip install --upgrade pip
if errorlevel 1 (
    echo Failed to upgrade pip.
    exit /b 1
)

echo [4/5] Installing Grudarin in editable mode
python -m pip install -e .
if errorlevel 1 (
    echo Failed to install Grudarin.
    exit /b 1
)

echo [5/5] Creating launcher helper
> grudarin.bat echo @echo off
>> grudarin.bat echo call "%%~dp0.venv\Scripts\activate.bat"
>> grudarin.bat echo python -m grudarin_app.cli %%*

if errorlevel 1 (
    echo Failed to create grudarin.bat.
    exit /b 1
)

echo Installation complete
echo Run one of the following commands:
echo   .venv\Scripts\grudarin --help
echo   grudarin.bat interfaces
echo   grudarin.bat scan
endlocal
