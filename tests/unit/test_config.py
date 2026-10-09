import pytest
from secret_keeper.config import Config, load_config


def test_defaults():
    assert load_config().port == 8080


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.2", "example.com"])
def test_forbid_remote_binding(host):
    with pytest.raises(ValueError):
        Config(host=host).validate()


@pytest.mark.parametrize("port", [0, 65536, True, "8080"])
def test_bad_ports(port):
    with pytest.raises(ValueError):
        Config(port=port).validate()


def test_unknown_key(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text('schema_version=1\n[proxy]\nsecret="bad"\n')
    with pytest.raises(ValueError):
        load_config(path)


def test_example():
    assert load_config("examples/proxy.toml").host == "127.0.0.1"
