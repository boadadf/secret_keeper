import argparse
import json
import sys
from . import __version__
from .config import load_config
from .engine import run


def main():
    parser = argparse.ArgumentParser(description="secret keeper pass-through inspecting proxy")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--config", help="Path to versioned TOML configuration")
    parser.add_argument("command", choices=["check", "start", "certificate"])
    args = parser.parse_args()
    try:
        config = load_config(args.config)
        if args.command == "check":
            print(json.dumps({"schema_version": 1, "listen_host": config.host,
                              "listen_port": config.port, "state_dir": str(config.state_dir)}))
            return 0
        if args.command == "certificate":
            cert = config.state_dir / "mitmproxy-ca-cert.pem"
            if not cert.is_file():
                raise ValueError("CA not initialized: start the proxy once, then stop it")
            print(cert)
            return 0
        print(f"Starting proxy on {config.host}:{config.port}; upstream TLS verification enabled",
              file=sys.stderr)
        return run(config)
    except (ValueError, OSError, RuntimeError) as exc:
        print(f"secret-keeper: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
