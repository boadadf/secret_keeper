import base64
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import pytest

ROOT=Path(__file__).resolve().parents[2]
def module(name,file):
    spec=importlib.util.spec_from_file_location(name,ROOT/file)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod
fmt=module("formatted_test","src/secret_keeper/readable_capture.py")
cap=module("payload_test","src/secret_keeper/payload_capture.py")

def record(body):return dict(transport="http",final_decision="ALLOW",timestamp="synthetic-time",flow_id="test",matched_rule_ids=[],body_available=True,raw_body_bytes=len(body.encode()),body_text=body)

def configured(tmp_path,**kwargs):
    opts=dict(capture_mode="full",capture_file=str(tmp_path/"out.jsonl"),capture_max_payload_bytes=1024,capture_max_file_bytes=73728,capture_backups=2,request_log=str(tmp_path/"audit.jsonl"))
    opts.update(kwargs);obj=cap.PayloadCapture();obj.configure(SimpleNamespace(**opts));return obj


def test_wrapped():
    rendered=fmt.readable(record("A"*5000))
    assert max(map(len,rendered.splitlines()))<=100
    assert "A"*101 not in rendered


def test_structure():
    rendered=fmt.readable(record(json.dumps({"messages":[{"role":"user","content":"hello"}]})))
    assert "messages:" in rendered and "[0]" in rendered and "content:" in rendered and "hello" in rendered
    assert '"messages": [{' not in rendered


def test_nested_json():
    rendered=fmt.readable(record(json.dumps({"content":json.dumps({"username":"synthetic"})})))
    assert "JSON inside a text field" in rendered and "username:" in rendered


def test_controls():
    rendered=fmt.readable(record("hello\x1b[31m\rspoof"))
    assert "\x1b" not in rendered and "\r" not in rendered
    assert r"\x1b" in rendered and r"\x0d" in rendered


def test_binary():
    r=record("");del r["body_text"];r["body_raw_base64"]=base64.b64encode(b"\xff"*200).decode()
    rendered=fmt.readable(r)
    assert "non-UTF-8" in rendered and r["body_raw_base64"] not in rendered


def test_raw_text_fallback():
    r=record("");del r["body_text"];r["body_raw_base64"]=base64.b64encode(b"synthetic plain text").decode()
    assert "synthetic plain text" in fmt.readable(r)


def test_truncation():
    r=record("hello");r["text_truncated"]=True
    assert "truncated" in fmt.readable(r)


def test_display_limit():
    out=fmt.readable(record("A"*20000),max_chars=1024)
    assert "display limit" in out and len(out)<1300


def test_companion(tmp_path):
    obj=configured(tmp_path)
    obj.write(SimpleNamespace(id="test"),"http",[],b'{"hello":"world"}','{"hello":"world"}')
    assert obj.path.exists() and obj.readable_path.exists()
    assert "hello:" in obj.readable_path.read_text()
    assert json.loads(obj.path.read_text())["body_text"]=='{"hello":"world"}'


def test_capture_disabled(tmp_path):
    obj=cap.PayloadCapture();obj.configure(SimpleNamespace(capture_mode="off"))
    obj.write(SimpleNamespace(id="test"),"http",[],b"hello","hello")
    assert not list(tmp_path.iterdir())


def test_readable_disabled(tmp_path):
    obj=configured(tmp_path,capture_readable=False)
    obj.write(SimpleNamespace(id="test"),"http",[],b"hello","hello")
    assert obj.path.exists() and obj.readable_path is None


def test_path_collision(tmp_path):
    assert not configured(tmp_path,capture_readable_file=str(tmp_path/"out.jsonl")).enabled


def test_rotation(tmp_path):
    obj=configured(tmp_path)
    for _ in range(100):obj.write(SimpleNamespace(id="test"),"http",[],b"a"*1024,"a"*1024)
    assert len(list(tmp_path.glob("out.jsonl*")))<=6
    assert all(p.stat().st_size<=obj.file_limit for p in tmp_path.glob("out.jsonl*"))


def test_viewer_filter(tmp_path):
    path=tmp_path/"input.jsonl"
    a=record("allowed text");b=record("blocked text");b["final_decision"]="BLOCK"
    path.write_text(json.dumps(a)+"\n"+json.dumps(b)+"\n")
    p=subprocess.run([sys.executable,str(ROOT/"scripts/read-capture.py"),str(path),"--decision","BLOCK"],capture_output=True,text=True)
    assert p.returncode==0 and "blocked text" in p.stdout and "allowed text" not in p.stdout


def test_viewer_no_overwrite(tmp_path):
    source=tmp_path/"in.jsonl";source.write_text(json.dumps(record("hello"))+"\n")
    dest=tmp_path/"out.txt";dest.write_text("keep")
    p=subprocess.run([sys.executable,str(ROOT/"scripts/read-capture.py"),str(source),"--output",str(dest)],capture_output=True,text=True)
    assert p.returncode!=0 and dest.read_text()=="keep"


def test_viewer_bad_record(tmp_path):
    source=tmp_path/"bad.jsonl";source.write_text('{"broken":')
    p=subprocess.run([sys.executable,str(ROOT/"scripts/read-capture.py"),str(source)],capture_output=True,text=True)
    assert p.returncode!=0 and "invalid/incomplete" in p.stderr


def test_quickstart_files():
    for file in ("scripts/setup-proxy.cmd","scripts/capture-requests.cmd","scripts/start-copilot.cmd","scripts/read-capture.cmd","requirements-proxy.txt"):
        assert (ROOT/file).is_file()
    launch=(ROOT/"scripts/capture-requests.cmd").read_text()
    assert 'SECRET_KEEPER_CAPTURE_MODE=off' in launch and 'capture_readable=true' in launch
    assert 'ssl_insecure=false' in launch


def test_setup_preserves_policy():
    text=(ROOT/"scripts/setup-proxy.cmd").read_text()
    assert 'if not exist "%SECRET_KEEPER_POLICY%"' in text
    assert 'Existing private policy retained' in text
