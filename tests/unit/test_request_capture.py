import importlib.util
import sys
import json
from pathlib import Path
from types import SimpleNamespace
import pytest


@pytest.fixture
def fixture(monkeypatch, tmp_path):
    logs = []
    context = SimpleNamespace(options=SimpleNamespace(request_log=str(tmp_path / "audit.jsonl")),
        log=SimpleNamespace(error=logs.append, info=logs.append))
    response = SimpleNamespace(make=lambda status, body, headers: SimpleNamespace(status_code=status, content=body))
    monkeypatch.setitem(sys.modules, "mitmproxy", SimpleNamespace(ctx=context,
        http=SimpleNamespace(HTTPFlow=object, Response=response)))
    path = Path(__file__).resolve().parents[2] / "src/secret_keeper/request_capture.py"
    spec = importlib.util.spec_from_file_location("patch04", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    addon = module.RequestCapture()
    addon.policy = module.validate_policy({"schema_version":1, "canary_enabled":False,
                                         "secrets_enabled":True, "dictionary":[]})
    req = SimpleNamespace(raw_content=b"hello", get_text=lambda strict: "hello", stream=True)
    flow = SimpleNamespace(id="test", request=req, response=None, websocket=SimpleNamespace(messages=[]))
    return module, addon, context, flow, logs


@pytest.mark.parametrize("text", ["hello", "Explain how passwords work", "Use an API key to authenticate",
    '{"messages":[{"role":"user","content":"hello"}]}',
    '{"session_id":"6bfdacf283704101a950be09dc54d1e7"}',
    "SECRET_KEEPER_CONFIDENTIAL_CANARY", "password = <redacted>"])
def test_normal_allowed(fixture, text):
    _, addon, _, _, _ = fixture
    assert addon.inspect(text) is None


@pytest.mark.parametrize("text", ['password = "Synthetic-Only-42"',
    '{"client_secret":"synthetic-only"}',
    "ghp_" + "A"*36, "AKIA" + "A"*16,
    "-----BEGIN PRIVATE KEY-----\nSYNTHETIC\n-----END PRIVATE KEY-----"])
def test_secrets_block(fixture, text):
    _, addon, _, _, _ = fixture
    assert addon.inspect(text)


def test_canary_opt_in_and_history(fixture):
    module, addon, _, _, _ = fixture
    addon.policy["canary_enabled"] = True
    found = addon.inspect(json.dumps({"messages":[{"content":module.CANARY},{"content":"hello"}]}))
    assert found["rule_id"] == "test_canary"
    assert found["location"].startswith("body.object")


def test_dictionary(fixture):
    _, addon, _, _, _ = fixture
    addon.policy["dictionary"] = [{"id":"customer-001","values":["Northstar Manufacturing"],"boundary":"whole_phrase"}]
    assert addon.inspect("NORTHSTAR   Manufacturing")
    assert addon.inspect("Northstar Manufacturingology") is None
    assert addon.inspect(json.dumps({"x":"Northstar Manufacturing"}))


def test_http_allow_and_block(fixture):
    _, addon, _, flow, _ = fixture
    addon.request(flow)
    assert flow.response is None
    flow.request.get_text = lambda strict: 'password="Synthetic-only"'
    addon.request(flow)
    assert flow.response.status_code == 422
    assert b"Synthetic-only" not in flow.response.content


def test_ws(fixture):
    _, addon, _, flow, _ = fixture
    msg = SimpleNamespace(from_client=True, content=b"hello", dropped=False)
    msg.drop = lambda: setattr(msg,"dropped",True)
    flow.websocket.messages.append(msg)
    addon.websocket_message(flow)
    assert not msg.dropped
    msg.content = b'password="Synthetic-only"'
    addon.websocket_message(flow)
    assert msg.dropped


def test_metadata_only(fixture, tmp_path):
    _, addon, _, flow, logs = fixture
    flow.request.get_text = lambda strict: '{"password":"SYNTHETIC_PRIVATE_VALUE"}'
    addon.request(flow)
    output = (tmp_path / "audit.jsonl").read_text() + str(logs)
    assert "SYNTHETIC_PRIVATE_VALUE" not in output
    assert '"location"' in output
    assert '"password"' not in output


def test_bad_policy(fixture):
    module, addon, _, flow, _ = fixture
    with pytest.raises(ValueError):
        module.validate_policy({"schema_version":1,"canary_enabled":False,"secrets_enabled":True,"dictionary":[{"id":"bad","values":[""],"boundary":"substring"}]})
    addon.policy_error = True
    addon.request(flow)
    assert flow.response.status_code == 422


def test_no_logging_enforces(fixture):
    _, addon, context, flow, _ = fixture
    context.options.request_log = ""
    flow.request.get_text = lambda strict: 'password="Synthetic-only"'
    addon.request(flow)
    assert flow.response.status_code == 422


def test_incoming_ignored(fixture):
    _, addon, _, flow, _ = fixture
    flow.websocket.messages.append(SimpleNamespace(from_client=False,content=b'password="Synthetic-only"'))
    addon.websocket_message(flow)


def test_decoding_error(fixture):
    _, addon, _, flow, _ = fixture
    def error(strict):
        raise ValueError("cannot decode")
    flow.request.get_text = error
    addon.request(flow)
    assert flow.response.status_code == 422
