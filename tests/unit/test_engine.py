from secret_keeper.config import Config
from secret_keeper.engine import build_command


def test_safe_engine_options():
    command = build_command(Config(), "mitmdump")
    assert "ssl_insecure=false" in command
    assert "flow_detail=0" in command
    assert "connection_strategy=lazy" in command
    assert "stream_large_bodies=0" in command
    assert "-w" not in command
    assert "-s" not in command
