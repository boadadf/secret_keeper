"""Real local HTTP/WS checks for expanded rules; reuses original harness."""
import base64
import importlib.util
import json
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
helper=Path(__file__).with_name("run_proxy_checks.py")
if not helper.is_file():raise SystemExit("FAIL: original run_proxy_checks.py is required")
spec=importlib.util.spec_from_file_location("upstream_helpers",helper)
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)

def rule(kind,**kw):return dict(id="test-rule",type=kind,enabled=True,action="block",**kw)
CASES=[
("url",rule("url_domain",domains=["example.internal"],include_subdomains=True),"https://reports.example.internal/doc"),
("email",rule("email",domains=["customer.example"],addresses=[],include_subdomains=True),"alice@customer.example"),
("ipv4",rule("ip_network",networks=["10.20.0.0/16"]),"10.20.1.2"),
("ipv6",rule("ip_network",networks=["fd12:3456:789a::/48"]),"fd12:3456:789a::1"),
("field",rule("field",fields=["username"],values=["synthetic-user-001"],case_sensitive=False),'{"username":"synthetic-user-001"}'),
("connection",rule("builtin",detector="connection_string"),"postgresql://user:synthetic@db.example/app"),
("resource",rule("resource",values=["synthetic-private-bucket-001"],case_sensitive=True),"synthetic-private-bucket-001"),
("percent",rule("exact_text",value=h.CANARY),"".join("%"+format(b,"02X") for b in h.CANARY.encode())),
("hex",rule("exact_text",value=h.CANARY),h.CANARY.encode().hex()),
("base64",rule("exact_text",value=h.CANARY),base64.b64encode(h.CANARY.encode()).decode()),
("token",rule("builtin",detector="supported_token_format"),"glpat-"+"A"*20),
("hash-audit",dict(rule("builtin",detector="hash_candidate"),action="audit"),"a"*64),
("entropy-audit",dict(rule("builtin",detector="entropy_candidate"),action="audit"),"Ab3Cd4Ef5Gh6Ij7Kl8Mn9Op0Qr1St2Uv3Wx4Yz5"),
("card-audit",dict(rule("builtin",detector="credit_card"),action="audit"),"4111 1111 1111 1111"),
("iban-audit",dict(rule("builtin",detector="iban"),action="audit"),"GB82 WEST 1234 5698 7654 32"),
("phone-audit",dict(rule("builtin",detector="phone_candidate"),action="audit"),"+44 20 7946 0958")]

def ws_allow(port,upstream,payload):
    import os
    with socket.create_connection(("127.0.0.1",port),timeout=8) as sock:
        stream=sock.makefile("rb")
        try:
            key=base64.b64encode(os.urandom(16)).decode()
            sock.sendall((f"GET http://127.0.0.1:{upstream.server_port}/ws HTTP/1.1\r\nHost: 127.0.0.1:{upstream.server_port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n").encode())
            h.require(b" 101 " in stream.readline(),"WS upgrade failed")
            while True:
                line=stream.readline();h.require(bool(line),"upgrade incomplete")
                if line==b"\r\n":break
            for content in (b"hello-before",payload,b"hello-after"):
                sock.sendall(h.frame(content,masked=True));h.require(h.read_frame(stream)==(1,content),"WS allowed echo missing")
            h.require(payload in upstream.snapshot("websocket"),"audit payload not received")
            sock.sendall(h.frame(b"",masked=True,opcode=8))
        finally:stream.close()

def check(name,rule,text,logging_enabled):
    upstream=h.Upstream();thread=threading.Thread(target=upstream.serve_forever,daemon=True);thread.start();proc=None
    with tempfile.TemporaryDirectory(prefix="secret-keeper-expanded-") as directory:
        tmp=Path(directory);port=h.free_port()
        policy={"schema_version":2,"inspection":{"decode_depth":2,"decoders":["percent","hex","base64"]},"rules":[rule]}
        (tmp/"policy.json").write_text(json.dumps(policy))
        exe=Path(sys.executable).parent/("mitmdump.exe" if sys.platform=="win32" else "mitmdump")
        h.require(exe.is_file(),"mitmdump missing")
        cmd=[str(exe),"--mode","regular","--listen-host","127.0.0.1","--listen-port",str(port),"--set","confdir="+str(tmp/"state"),"--set","connection_strategy=lazy","--set","flow_detail=0","--set","termlog_verbosity=error","-s",str(ROOT/"src/secret_keeper/request_capture.py"),"--set","secret_keeper_policy="+str(tmp/"policy.json"),"--set","request_log="+(str(tmp/"audit.jsonl") if logging_enabled else "")]
        try:
            with (tmp/"proxy.log").open("wb") as log:
                proc=subprocess.Popen(cmd,stdout=log,stderr=subprocess.STDOUT);deadline=time.monotonic()+20
                while True:
                    h.require(proc.poll() is None,"proxy exited")
                    try:
                        with socket.create_connection(("127.0.0.1",port),timeout=.3):break
                    except OSError:
                        h.require(time.monotonic()<deadline,"startup timeout");time.sleep(.1)
                good=b"hello-control";payload=text.encode()
                status,_=h.post(port,upstream.server_port,good)
                h.require(status==200 and good in upstream.snapshot("http"),"HTTP allow control failed")
                blocked=rule["action"]=="block"
                status,_=h.post(port,upstream.server_port,payload)
                h.require(status==(422 if blocked else 200),"HTTP decision incorrect")
                status,_=h.post(port,upstream.server_port,b"hello-after")
                h.require(status==200,"HTTP after-control failed")
                h.require((payload in upstream.snapshot("http"))==(not blocked),"HTTP upstream receipt incorrect")
                if blocked:h.ws_checks(port,upstream.server_port,upstream,payload,name)
                else:ws_allow(port,upstream,payload)
                if logging_enabled:
                    records=[json.loads(line) for line in (tmp/"audit.jsonl").read_text().splitlines()]
                    for transport in ("http","websocket"):
                        h.require(any(r.get("transport")==transport and r.get("rule_id")=="test-rule" and r.get("decision")==("BLOCK" if blocked else "AUDIT") for r in records),"missing match audit")
                print("PASS",name,"HTTP + WebSocket; audit="+str(logging_enabled),flush=True)
        except Exception:
            print((tmp/"proxy.log").read_text(errors="replace"),file=sys.stderr);raise
        finally:
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:proc.wait(timeout=5)
                except subprocess.TimeoutExpired:proc.kill();proc.wait()
            upstream.shutdown();upstream.server_close();thread.join(timeout=3)

if __name__=="__main__":
    try:
        for logging_enabled in (True,False):
            for name,rule,text in CASES:check(name,rule,text,logging_enabled)
        print("PASS: 64 expanded transport/case checks. Local HTTP/WS only.")
    except Exception as error:
        print("FAIL:",str(error),file=sys.stderr);sys.exit(1)
