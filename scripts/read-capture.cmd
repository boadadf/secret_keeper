@echo off
setlocal
cd /d "%~dp0.."
if not exist ".venv\Scripts\python.exe" exit /b 2
if "%~1"=="" (
  if not defined SECRET_KEEPER_STATE set "SECRET_KEEPER_STATE=%LOCALAPPDATA%\SecretKeeper"
  call :default
  exit /b
)
".venv\Scripts\python.exe" "scripts\read-capture.py" %*
exit /b %ERRORLEVEL%
:default
".venv\Scripts\python.exe" "scripts\read-capture.py" "%SECRET_KEEPER_STATE%\captures\outbound.jsonl"
exit /b %ERRORLEVEL%
