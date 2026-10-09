$ErrorActionPreference = "Stop"

Set-Location (Split-Path $PSScriptRoot -Parent)

py -3.12 -m venv .venv
if ($LASTEXITCODE -ne 0) {
    throw "Python 3.12 is required for this source setup script."
}

& .\.venv\Scripts\python.exe -m pip install -e ".[dev]"
if ($LASTEXITCODE -ne 0) {
    throw "Dependency installation failed."
}

& .\.venv\Scripts\python.exe -m pytest
if ($LASTEXITCODE -ne 0) {
    throw "Tests failed."
}