@echo off
rem Builds dist\VirtualDiskBrowser.exe (GUI) and dist\vdbrowser-cli.exe (console) with PyInstaller.
setlocal
cd /d "%~dp0"

python -m pip install --upgrade -r requirements.txt pyinstaller || goto :fail

python -m PyInstaller --noconfirm --clean --onefile --windowed ^
  --name VirtualDiskBrowser --icon assets\icon.ico --add-data "assets/icon.png:assets" main.py || goto :fail

python -m PyInstaller --noconfirm --clean --onefile --console ^
  --name vdbrowser-cli --icon assets\icon.ico --add-data "assets/icon.png:assets" main.py || goto :fail

echo.
echo Built:
echo   dist\VirtualDiskBrowser.exe     (double-click; or drag a disk image onto it)
echo   dist\vdbrowser-cli.exe   (command line: vdbrowser-cli info disk.vmdk)
exit /b 0

:fail
echo Build failed.
exit /b 1
