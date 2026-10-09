@echo off
setlocal
cd /d "%~dp0.."
if not defined LOCALAPPDATA exit /b 2
if not defined SECRET_KEEPER_STATE set "SECRET_KEEPER_STATE=%LOCALAPPDATA%\SecretKeeper"
if not exist "%SECRET_KEEPER_STATE%\mitmproxy-ca-cert.pem" (
  echo ERROR: Start the proxy first to create its local CA certificate.
  exit /b 2
)
where copilot >nul 2>&1
if errorlevel 1 (
  echo ERROR: Install GitHub Copilot CLI and complete its account setup first.
  exit /b 2
)
set "HTTPS_PROXY=http://127.0.0.1:8080"
set "HTTP_PROXY=http://127.0.0.1:8080"
set "NODE_EXTRA_CA_CERTS=%SECRET_KEEPER_STATE%\mitmproxy-ca-cert.pem"
echo Copilot proxy configured for this process. Verify with a synthetic block test.
call copilot %*
exit /b %ERRORLEVEL%
