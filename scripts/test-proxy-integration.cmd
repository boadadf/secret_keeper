@echo off
setlocal
cd /d "%~dp0.."
if not exist ".venv\Scripts\python.exe" (
  echo ERROR: Project virtual environment is missing.
  exit /b 2
)
".venv\Scripts\python.exe" "tests\integration\run_proxy_checks.py"
exit /b %ERRORLEVEL%
