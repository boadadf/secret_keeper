from pathlib import Path
import sys
import subprocess


def build_command(config, executable):
    return [
        executable, "--mode", "regular",
        "--listen-host", config.host, "--listen-port", str(config.port),
        "--set", f"confdir={config.state_dir}",
        "--set", "ssl_insecure=false",
        "--set", "flow_detail=0",
        "--set", "termlog_verbosity=error",
        "--set", "connection_strategy=lazy",
        "--set", "stream_large_bodies=0",
    ]


def run(config):
    engine_name = "mitmdump.exe" if sys.platform == "win32" else "mitmdump"
    engine_path = Path(sys.executable).parent / engine_name
    if not engine_path.is_file():
        raise RuntimeError(
            f"Proxy engine missing: {engine_path}. "
            "Install dependencies in this environment."
        )
    executable = str(engine_path)
    config.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not config.state_dir.is_dir():
        raise RuntimeError("Invalid state directory")
    # Existing directory permissions and Windows ACLs are an operator responsibility.
    command = build_command(config, executable)
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL)
    try:
        return process.wait()
    except KeyboardInterrupt:
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        return 130
