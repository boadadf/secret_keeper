from dataclasses import dataclass
from pathlib import Path
import ipaddress
import os
import tomllib


def default_state_dir():
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA", Path.home())) / "SecretKeeper"
    return Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")) / "secret-keeper"


@dataclass(frozen=True)
class Config:
    host: str = "127.0.0.1"
    port: int = 8080
    state_dir: Path = default_state_dir()

    def validate(self):
        try:
            address = ipaddress.ip_address(self.host)
        except ValueError as exc:
            raise ValueError("listen_host must be a numeric loopback address") from exc
        if not address.is_loopback:
            raise ValueError("This release permits loopback listeners only")
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError("listen_port must be an integer from 1 to 65535")
        return self


def load_config(path=None):
    if path is None:
        return Config().validate()
    with Path(path).open("rb") as stream:
        data = tomllib.load(stream)
    if set(data) - {"schema_version", "proxy"}:
        raise ValueError("Unknown top-level configuration field")
    if type(data.get("schema_version")) is not int or data["schema_version"] != 1:
        raise ValueError("schema_version must be 1")
    proxy = data.get("proxy", {})
    if not isinstance(proxy, dict):
        raise ValueError("proxy must be a table")
    if set(proxy) - {"listen_host", "listen_port", "state_dir"}:
        raise ValueError("Unknown proxy configuration field")
    return Config(
        host=proxy.get("listen_host", "127.0.0.1"),
        port=proxy.get("listen_port", 8080),
        state_dir=Path(proxy.get("state_dir", default_state_dir())).expanduser().absolute(),
    ).validate()
