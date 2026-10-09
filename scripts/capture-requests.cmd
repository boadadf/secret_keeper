@echo off
setlocal

rem Run from the repository root.
cd /d "%~dp0.."

if not defined LOCALAPPDATA (
  echo ERROR: LOCALAPPDATA is not defined.
  exit /b 2
)

if not exist ".venv\Scripts\mitmdump.exe" (
  echo ERROR: Install project dependencies first.
  exit /b 2
)

if not exist "src\secret_keeper\request_capture.py" (
  echo ERROR: Secret Keeper proxy addon was not found.
  exit /b 2
)

set "STATE=%LOCALAPPDATA%\SecretKeeper"
set "LOG=%STATE%\logs\audit.jsonl"

rem Allow an explicitly supplied private policy path.
if not defined SECRET_KEEPER_POLICY (
  set "SECRET_KEEPER_POLICY=%STATE%\secret-keeper-policy.json"
)

if not exist "%SECRET_KEEPER_POLICY%" (
  echo ERROR: Private policy file was not found.
  echo Expected policy: "%SECRET_KEEPER_POLICY%"
  echo Create it from config\secret-keeper-policy.example.json.
  echo Or set SECRET_KEEPER_POLICY to your existing private policy path.
  exit /b 2
)

echo Secret Keeper experimental content-policy proxy
echo Listen: 127.0.0.1:8080
echo Policy: "%SECRET_KEEPER_POLICY%"
echo Audit log: "%LOG%"
echo Stop with Ctrl+C.
echo.

".venv\Scripts\mitmdump.exe" ^
  --mode regular ^
  --listen-host 127.0.0.1 ^
  --listen-port 8080 ^
  --set "confdir=%STATE%" ^
  --set ssl_insecure=false ^
  --set flow_detail=0 ^
  --set termlog_verbosity=error ^
  --set connection_strategy=lazy ^
  --set body_size_limit=10m ^
  -s src\secret_keeper\request_capture.py ^
  --set "request_log=%LOG%" ^
  --set "secret_keeper_policy=%SECRET_KEEPER_POLICY%"

exit /b %ERRORLEVEL%