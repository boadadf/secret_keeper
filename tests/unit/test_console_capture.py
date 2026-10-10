import importlib.util
import io
from pathlib import Path
from types import SimpleNamespace
import pytest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location("console_capture_test",ROOT/"src/secret_keeper/payload_capture.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def configured(tmp_path,**changes):
    opts=dict(sk_console_capture=True,capture_mode="off",capture_max_payload_bytes=1024)
    opts.update(changes)
    obj=m.PayloadCapture();obj.configure(SimpleNamespace(**opts));return obj

def flow():
    return SimpleNamespace(id="test-flow",request=SimpleNamespace(host="api.example.test",port=443))

@pytest.mark.parametrize("transport",["http","websocket"])
def test_live_without_file(tmp_path,capsys,transport):
    obj=configured(tmp_path)
    obj.write(flow(),transport,[],b'{"messages":[{"role":"user","content":"Hello live"}]}','{"messages":[{"role":"user","content":"Hello live"}]}')
    out=capsys.readouterr().out
    assert "Hello live" in out and "ALLOW" in out and "api.example.test:443" in out
    assert not obj.enabled and not list(tmp_path.iterdir())

@pytest.mark.parametrize("action",["block","audit"])
def test_match_withholds_entire_payload(tmp_path,capsys,action):
    obj=configured(tmp_path)
    obj.write(flow(),"http",[{"rule_id":"synthetic-rule","action":action}],b"synthetic-secret","synthetic-secret")
    out=capsys.readouterr().out
    assert "REDACTED" in out and "synthetic-secret" not in out and "synthetic-rule" in out

def test_unavailable_decoded_text_is_hidden(tmp_path,capsys):
    obj=configured(tmp_path);obj.write(flow(),"http",[],b"synthetic-secret")
    out=capsys.readouterr().out
    assert "REDACTED" in out and "synthetic-secret" not in out

def test_default_silent(tmp_path,capsys):
    obj=configured(tmp_path,sk_console_capture=False);obj.write(flow(),"http",[],b"hello","hello")
    assert capsys.readouterr().out==""

def test_truncation(tmp_path,capsys):
    obj=configured(tmp_path);obj.write(flow(),"http",[],b"a"*1500,"a"*1500)
    out=capsys.readouterr().out
    assert "truncated" in out and "a"*1025 not in out

def test_console_failure_does_not_raise(tmp_path,monkeypatch):
    class Broken:
        def write(self,text):raise BrokenPipeError()
    obj=configured(tmp_path);monkeypatch.setattr(m.sys,"stdout",Broken())
    obj.write(flow(),"http",[],b"hello","hello")

def test_console_and_file_are_independent(tmp_path,capsys):
    path=tmp_path/"capture.jsonl"
    obj=configured(tmp_path,capture_mode="full",capture_file=str(path),capture_max_file_bytes=73728)
    obj.write(flow(),"http",[{"rule_id":"synthetic-rule","action":"block"}],b"synthetic-secret","synthetic-secret")
    assert "synthetic-secret" not in capsys.readouterr().out
    assert "synthetic-secret" in path.read_text()

@pytest.mark.parametrize("flag",["true",1,None])
def test_invalid_flag_disabled(tmp_path,capsys,flag):
    obj=configured(tmp_path,sk_console_capture=flag);obj.write(flow(),"http",[],b"hello","hello")
    assert not obj.console and capsys.readouterr().out==""

def test_unicode_fallback(tmp_path,monkeypatch):
    data=[]
    class Ascii:
        encoding="ascii"
        def write(self,text):
            text.encode("ascii");data.append(text)
        def flush(self):pass
    obj=configured(tmp_path);monkeypatch.setattr(m.sys,"stdout",Ascii())
    obj.write(flow(),"http",[],"Hello €".encode(),"Hello €")
    assert data and "Hello" in data[0]

def test_escape_sequences_are_not_emitted(tmp_path,capsys):
    obj=configured(tmp_path);obj.write(flow(),"http",[],b"\x1b[2J","\x1b[2J")
    out=capsys.readouterr().out
    assert "\x1b" not in out and "\\x1b" in out
