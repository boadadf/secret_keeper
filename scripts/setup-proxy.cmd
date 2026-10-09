@echo off
setlocal
cd /d "%~dp0.."
where py >nul 2>&1
if errorlevel 1 (
  echo ERROR: Install Python 3.12 with the Windows Python launcher first.
  exit /b 2
)
if not exist ".venv\Scripts\python.exe" (
  py -3.12 -m venv .venv
  if errorlevel 1 exit /b 2
)
".venv\Scripts\python.exe" -m pip install -r requirements-proxy.txt
if errorlevel 1 exit /b 2
if not defined LOCALAPPDATA exit /b 2
if not defined SECRET_KEEPER_STATE set "SECRET_KEEPER_STATE=%LOCALAPPDATA%\SecretKeeper"
if not defined SECRET_KEEPER_POLICY set "SECRET_KEEPER_POLICY=%SECRET_KEEPER_STATE%\secret-keeper-policy.json"
if not exist "config\secret-keeper-policy.example.json" (
  echo ERROR: Public policy example is missing. Install all release files.
  exit /b 2
)
for %%I in ("%SECRET_KEEPER_POLICY%") do if not exist "%%~dpI" mkdir "%%~dpI"
if not exist "%SECRET_KEEPER_POLICY%" (
  copy /Y "config\secret-keeper-policy.example.json" "%SECRET_KEEPER_POLICY%" >nul
  if errorlevel 1 exit /b 2
  echo Created private policy from fictional example. Review it before use.
) else (
  echo Existing private policy retained.
)
echo Setup completed for the standalone proxy workflow.
echo Next: scripts\capture-requests.cmd
exit /b 0
