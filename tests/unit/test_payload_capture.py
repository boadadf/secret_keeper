import base64
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import pytest
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location("capture_helpers_test",ROOT/"src/secret_keeper/payload_capture.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def configured(tmp_path,**kwargs):
    options=dict(capture_mode="full",capture_file=str(tmp_path/"payloads.jsonl"),request_log=str(tmp_path/"audit.jsonl"),capture_max_payload_bytes=1024,capture_max_file_bytes=73728,capture_backups=2)
    options.update(kwargs);obj=m.PayloadCapture();obj.configure(SimpleNamespace(**options));return obj

def read(path):return [json.loads(line) for line in path.read_text().splitlines()]

def test_off_default(tmp_path):
    obj=m.PayloadCapture();obj.configure(SimpleNamespace(request_log=""));obj.write(SimpleNamespace(id="test"),"http",[],b"synthetic")
    assert not obj.enabled and not list(tmp_path.iterdir())

@pytest.mark.parametrize("transport",["http","websocket"])
@pytest.mark.parametrize("blocked",[False,True])
def test_capture(tmp_path,transport,blocked):
    obj=configured(tmp_path);matches=[{"rule_id":"test-rule","action":"block"}] if blocked else []
    obj.write(SimpleNamespace(id="test"),transport,matches,b"synthetic","synthetic",0 if transport=="websocket" else None)
    record=read(obj.path)[0]
    assert base64.b64decode(record["body_raw_base64"])==b"synthetic" and record["body_text"]=="synthetic"
    assert record["final_decision"]==("BLOCK" if blocked else "ALLOW")
    assert record["capture_stage"]=="attempted_outbound" and not record["raw_truncated"]

def test_truncation(tmp_path):
    obj=configured(tmp_path);obj.write(SimpleNamespace(id="test"),"http",[],b"a"*1500,"a"*1500)
    record=read(obj.path)[0]
    assert record["raw_truncated"] and record["text_truncated"]
    assert len(base64.b64decode(record["body_raw_base64"]))==1024 and record["raw_body_bytes"]==1500

def test_rotation(tmp_path):
    obj=configured(tmp_path)
    for _ in range(150):obj.write(SimpleNamespace(id="test"),"http",[],b"a"*1024,"a"*1024)
    paths=[p for p in [obj.path,Path(str(obj.path)+".1"),Path(str(obj.path)+".2")] if p.exists()]
    assert 1<=len(paths)<=3 and Path(str(obj.path)+".1").exists()
    assert all(p.stat().st_size<=obj.file_limit for p in paths)
    for p in paths:assert read(p)

def test_zero_backups(tmp_path):
    obj=configured(tmp_path,capture_backups=0)
    for _ in range(80):obj.write(SimpleNamespace(id="test"),"http",[],b"a"*1024,"a"*1024)
    assert obj.path.exists() and not Path(str(obj.path)+".1").exists()

@pytest.mark.parametrize("options",[{"capture_mode":"unknown"},{"capture_file":""},{"capture_backups":11},{"capture_max_payload_bytes":0},{"capture_max_file_bytes":1024}])
def test_bad_config(tmp_path,options):assert not configured(tmp_path,**options).enabled

def test_same_audit_path(tmp_path):assert not configured(tmp_path,request_log=str(tmp_path/"payloads.jsonl")).enabled

def test_missing_body(tmp_path):
    obj=configured(tmp_path);obj.write(SimpleNamespace(id="test"),"http",[{"rule_id":"body_unavailable","action":"block"}])
    record=read(obj.path)[0];assert not record["body_available"] and "body_raw_base64" not in record

def test_write_failure(tmp_path):
    obj=configured(tmp_path);obj.path.mkdir();obj.write(SimpleNamespace(id="test"),"http",[{"rule_id":"test-rule","action":"block"}],b"synthetic")
    assert obj.path.is_dir()

def test_utf8_boundary(tmp_path):
    obj=configured(tmp_path);obj.write(SimpleNamespace(id="test"),"http",[],b"","€"*400)
    record=read(obj.path)[0];assert record["text_truncated"] and len(record["body_text"].encode())<=1024
