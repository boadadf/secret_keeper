@echo off
setlocal EnableExtensions DisableDelayedExpansion
cd /d "%~dp0.."
if errorlevel 1 (
  echo ERROR: Cannot enter the project directory.
  exit /b 2
)

for %%F in (requirements-proxy.txt src\secret_keeper\request_capture.py src\secret_keeper\rules.py src\secret_keeper\payload_capture.py src\secret_keeper\readable_capture.py src\secret_keeper\ws_response_builder.py) do (
  if not exist "%%F" (
    echo ERROR: Required repository file missing: %%F
    echo Update the checkout or extract all required release files.
    exit /b 2
  )
)
if not defined LOCALAPPDATA (
  echo ERROR: LOCALAPPDATA is missing. Run this Windows script from Windows CMD.
  exit /b 2
)
if not defined SECRET_KEEPER_STATE set "SECRET_KEEPER_STATE=%LOCALAPPDATA%\SecretKeeper"
if not defined SECRET_KEEPER_POLICY set "SECRET_KEEPER_POLICY=%SECRET_KEEPER_STATE%\secret-keeper-policy.json"

if exist ".venv\Scripts\python.exe" goto existing_venv
if exist ".venv" (
  echo ERROR: .venv exists but has no Windows Python executable.
  echo Rename that directory after checking it, then rerun setup.
  echo A Linux or WSL virtual environment cannot be used by this Windows launcher.
  exit /b 2
)

set "PY_CMD="
set "PY_ARG="
if defined VIRTUAL_ENV call :try_python "%VIRTUAL_ENV%\Scripts\python.exe"
if not defined PY_CMD call :try_python python
if not defined PY_CMD call :try_python py -3
if not defined PY_CMD call :try_python py -3.14
if not defined PY_CMD call :try_python py -3.13
if not defined PY_CMD call :try_python py -3.12
if not defined PY_CMD (
  echo ERROR: No usable Python 3.12, 3.13 or 3.14 interpreter was found.
  echo Install ONE supported Windows Python version, or activate your existing environment.
  echo You do not need all of those Python versions or the py launcher.
  exit /b 2
)
echo Creating the project .venv using:
"%PY_CMD%" %PY_ARG% -c "import sys; print(sys.executable); print(sys.version)"
"%PY_CMD%" %PY_ARG% -m venv .venv
if errorlevel 1 (
  echo ERROR: Could not create .venv. Check the interpreter, permissions and available disk space.
  echo A partially created .venv may need to be renamed before retrying.
  exit /b 2
)
goto validate_venv

:existing_venv
echo Reusing the existing project .venv.

:validate_venv
".venv\Scripts\python.exe" -c "import sys; print('Python:', sys.version); print('Interpreter:', sys.executable); sys.exit(0 if sys.version_info.major == 3 and 12 <= sys.version_info.minor <= 14 else 1)"
if errorlevel 1 (
  echo ERROR: The existing .venv is broken or not based on Python 3.12 through 3.14.
  echo It has NOT been deleted or overwritten.
  echo Rename it after checking it, then rerun setup with a supported Python available.
  exit /b 2
)
".venv\Scripts\python.exe" -m pip --version
if errorlevel 1 (
  echo ERROR: pip is unavailable in the project environment.
  echo Try: .venv\Scripts\python.exe -m ensurepip --upgrade
  exit /b 2
)
echo Installing the proxy requirements into the project .venv...
".venv\Scripts\python.exe" -m pip install -r requirements-proxy.txt
if errorlevel 1 (
  echo ERROR: Dependency installation failed. Review the pip error above.
  echo Setup has not completed. Check network access, package-index settings and dependency compatibility.
  exit /b 2
)
".venv\Scripts\python.exe" -m pip check
if errorlevel 1 (
  echo ERROR: Installed dependencies are inconsistent. Review pip check output above.
  exit /b 2
)
if not exist ".venv\Scripts\mitmdump.exe" (
  echo ERROR: mitmdump.exe was not installed into the project environment.
  exit /b 2
)
".venv\Scripts\mitmdump.exe" --version
if errorlevel 1 (
  echo ERROR: mitmdump cannot start in this environment.
  exit /b 2
)
".venv\Scripts\python.exe" -B -c "import runpy; runpy.run_path('src/secret_keeper/request_capture.py', run_name='secret_keeper_setup_check'); print('Addon import check passed.')"
if errorlevel 1 (
  echo ERROR: The proxy addon or a required helper could not be imported.
  echo Review the traceback above. Setup has not completed.
  exit /b 2
)

if exist "%SECRET_KEEPER_POLICY%" goto policy_exists
if not exist "config\secret-keeper-policy.example.json" (
  echo ERROR: Public policy example is missing and no private policy exists.
  exit /b 2
)
for %%I in ("%SECRET_KEEPER_POLICY%") do if not exist "%%~dpI" mkdir "%%~dpI"
if errorlevel 1 (
  echo ERROR: Could not create the private policy directory.
  exit /b 2
)
copy /Y "config\secret-keeper-policy.example.json" "%SECRET_KEEPER_POLICY%" >nul
if errorlevel 1 (
  echo ERROR: Could not initialize the private policy.
  exit /b 2
)
echo Created private policy from fictional example. Review it before use.
goto validate_policy

:policy_exists
echo Existing private policy retained.

:validate_policy
".venv\Scripts\python.exe" -B -c "import importlib.util, pathlib, sys; s=importlib.util.spec_from_file_location('secret_keeper_setup_rules', 'src/secret_keeper/rules.py'); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); import json; p=m.validate_policy(json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))); print('Policy validated:', len(p['rules']), 'rules and', len(p.get('replacements', [])), 'replacement rules.')" "%SECRET_KEEPER_POLICY%"
if errorlevel 1 (
  echo ERROR: The private policy is invalid or unreadable. It has NOT been overwritten.
  echo Review the error above and correct the existing policy.
  exit /b 2
)
echo.
echo Setup completed for the standalone proxy workflow.
echo Policy: "%SECRET_KEEPER_POLICY%"
echo Next: scripts\capture-requests.cmd copilot
exit /b 0

:try_python
if defined PY_CMD exit /b 0
"%~1" %~2 -c "import sys; sys.exit(0 if sys.version_info.major == 3 and 12 <= sys.version_info.minor <= 14 else 1)" >nul 2>&1
if errorlevel 1 exit /b 0
set "PY_CMD=%~1"
set "PY_ARG=%~2"
exit /b 0
