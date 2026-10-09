# Contributing

Use Python 3.12 and `pip install -e '.[dev]'`. Run `python -m pytest` and
`python -m ruff check .`. Add synthetic tests for behavior changes. Do not introduce
payload logging, disabled certificate verification, remote binding, telemetry or
implicit certificate installation. Document architecture changes in an ADR.
Use synthetic fixtures only. Never include secrets or captured user traffic.
