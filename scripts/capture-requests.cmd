@echo off
setlocal
cd /d "%~dp0.."
set "WS_CLIENT=copilot"
if not "%~1"=="" set "WS_CLIENT=%~1"
if /I not "%WS_CLIENT%"=="copilot" if /I not "%WS_CLIENT%"=="none" (
  echo ERROR: Expected copilot or none.
  exit /b 2
)
if /I "%WS_CLIENT%"=="copilot" set "WS_CLIENT=copilot"
if /I "%WS_CLIENT%"=="none" set "WS_CLIENT=none"
if not defined SECRET_KEEPER_FLOW_DETAIL set "SECRET_KEEPER_FLOW_DETAIL=1"
if not defined LOCALAPPDATA exit /b 2
if not exist ".venv\Scripts\mitmdump.exe" (
  echo ERROR: Run scripts\setup-proxy.cmd first.
  exit /b 2
)
for %%F in (src\secret_keeper\request_capture.py src\secret_keeper\rules.py src\secret_keeper\payload_capture.py src\secret_keeper\readable_capture.py src\secret_keeper\ws_response_builder.py) do (
  if not exist "%%F" (
    echo ERROR: Required release file missing: %%F
    exit /b 2
  )
)
if not defined SECRET_KEEPER_STATE set "SECRET_KEEPER_STATE=%LOCALAPPDATA%\SecretKeeper"
if not defined SECRET_KEEPER_POLICY set "SECRET_KEEPER_POLICY=%SECRET_KEEPER_STATE%\secret-keeper-policy.json"
if not defined SECRET_KEEPER_CAPTURE_MODE set "SECRET_KEEPER_CAPTURE_MODE=off"
if /I not "%SECRET_KEEPER_CAPTURE_MODE%"=="off" if /I not "%SECRET_KEEPER_CAPTURE_MODE%"=="full" (
  echo ERROR: SECRET_KEEPER_CAPTURE_MODE must be off or full.
  exit /b 2
)
if not exist "%SECRET_KEEPER_POLICY%" (
  echo ERROR: Private policy missing. Run scripts\setup-proxy.cmd first.
  exit /b 2
)
set "MODE=off"
if /I "%SECRET_KEEPER_CAPTURE_MODE%"=="full" set "MODE=full"
set "STATE=%SECRET_KEEPER_STATE%"
set "LOG=%STATE%\logs\audit.jsonl"
set "CAPTURE=%STATE%\captures\outbound.jsonl"
echo Secret Keeper: 127.0.0.1:8080
echo Policy: "%SECRET_KEEPER_POLICY%"
echo Capture: %MODE%
echo WebSocket block reply: %WS_CLIENT%
if "%MODE%"=="full" echo Readable capture: "%CAPTURE%.txt"
echo Stop with Ctrl+C.
".venv\Scripts\mitmdump.exe" --mode regular --listen-host 127.0.0.1 --listen-port 8080 --set "confdir=%STATE%" --set ssl_insecure=false --set "flow_detail=%SECRET_KEEPER_FLOW_DETAIL%" --set termlog_verbosity=info --set connection_strategy=lazy --set body_size_limit=10m -s src\secret_keeper\request_capture.py --set "request_log=%LOG%" --set "secret_keeper_policy=%SECRET_KEEPER_POLICY%" --set "capture_mode=%MODE%" --set "capture_file=%CAPTURE%" --set capture_readable=true --set "secret_keeper_ws_client=%WS_CLIENT%"
exit /b %ERRORLEVEL%
