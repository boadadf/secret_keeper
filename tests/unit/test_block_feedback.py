import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace
import pytest
ROOT=Path(__file__).resolve().parents[2]

@pytest.fixture
def addon(monkeypatch):
    ctx=SimpleNamespace(options=SimpleNamespace(request_log=""))
    response=SimpleNamespace(make=lambda code,body,headers:SimpleNamespace(status_code=code,content=body,headers=headers))
    monkeypatch.setitem(sys.modules,"mitmproxy",SimpleNamespace(ctx=ctx,http=SimpleNamespace(HTTPFlow=object,Response=response)))
    spec=importlib.util.spec_from_file_location("sk10_test",ROOT/"src/secret_keeper/request_capture.py")
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    obj=mod.RequestCapture()
    obj.policy=mod.validate_policy({"schema_version":2,"rules":[{"id":"synthetic-rule","type":"exact_text","enabled":True,"action":"block","value":"SYNTHETIC"}]})
    obj.policy_error=False
    message=SimpleNamespace(from_client=True,content=b"SYNTHETIC",dropped=False)
    message.drop=lambda:setattr(message,"dropped",True)
    f=SimpleNamespace(id="test-flow",killable=True,killed=False,websocket=SimpleNamespace(messages=[message]),response=None,request=SimpleNamespace(raw_content=b"SYNTHETIC",get_text=lambda strict:"SYNTHETIC"))
    def kill():
        assert message.dropped
        f.killed=True;f.killable=False
    f.kill=kill
    return obj,f,message

def test_websocket_drop_then_kill(addon):
    obj,f,message=addon;obj.websocket_message(f)
    assert message.dropped and f.killed

def test_audit_does_not_kill(addon):
    obj,f,message=addon;obj.policy["rules"][0]["action"]="audit";obj.websocket_message(f)
    assert not message.dropped and not f.killed

def test_allowed_does_not_kill(addon):
    obj,f,message=addon;message.content=b"hello";obj.websocket_message(f)
    assert not message.dropped and not f.killed

def test_server_message_untouched(addon):
    obj,f,message=addon;message.from_client=False;obj.websocket_message(f)
    assert not message.dropped and not f.killed

def test_not_killable_still_drops(addon,caplog):
    obj,f,message=addon;f.killable=False;obj.websocket_message(f)
    assert message.dropped and not f.killed and "termination unavailable" in caplog.text

def test_kill_failure_still_drops(addon,caplog):
    obj,f,message=addon
    def fail():raise RuntimeError("synthetic error")
    f.kill=fail;obj.websocket_message(f)
    assert message.dropped and "termination failed" in caplog.text

def test_http_explicit_error(addon):
    obj,f,message=addon;obj.request(f)
    error=json.loads(f.response.content)["error"]
    assert f.response.status_code==422 and error["retryable"] is False
    assert error["code"]=="secret_keeper_blocked" and error["rule_ids"]==["synthetic-rule"]
    assert f.response.headers["X-Secret-Keeper-Blocked"]=="true"
    assert b"SYNTHETIC" not in f.response.content

def test_notice_does_not_contain_secret(addon,caplog):
    obj,f,message=addon;obj.websocket_message(f)
    assert "SECRET KEEPER REJECTED" in caplog.text and "SYNTHETIC" not in caplog.text

def test_policy_error_terminates(addon):
    obj,f,message=addon;obj.policy_error=True;obj.websocket_message(f)
    assert message.dropped and f.killed
