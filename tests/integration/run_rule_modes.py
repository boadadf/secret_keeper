"""Schema-2 network checks using the original integration harness helpers."""
import importlib.util
import json
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
helper = Path(__file__).with_name("run_proxy_checks.py")
if not helper.is_file():
    raise SystemExit("FAIL: original tests/integration/run_proxy_checks.py is required")
spec=importlib.util.spec_from_file_location("local_helpers",helper)
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)


def check(mode, log_enabled):
    upstream=h.Upstream()
    thread=threading.Thread(target=upstream.serve_forever,daemon=True);thread.start()
    proc=None
    with tempfile.TemporaryDirectory(prefix="secret-keeper-rules-") as directory:
        temp=Path(directory);port=h.free_port()
        rules=[{"id":"mode-rule","enabled":mode!="disabled","type":"exact_text","value":h.CANARY,
                "action":"audit" if mode in ("audit","conflict") else "block"}]
        if mode=="conflict":
            rules.append({"id":"blocking-rule","enabled":True,"type":"exact_text","value":h.CANARY,"action":"block"})
        (temp/"policy.json").write_text(json.dumps({"schema_version":2,"rules":rules}))
        exe=Path(sys.executable).parent/("mitmdump.exe" if sys.platform=="win32" else "mitmdump")
        h.require(exe.is_file(),"mitmdump missing")
        command=[str(exe),"--mode","regular","--listen-host","127.0.0.1","--listen-port",str(port),
                 "--set","confdir="+str(temp/"state"),"--set","connection_strategy=lazy",
                 "--set","flow_detail=0","--set","termlog_verbosity=error",
                 "-s",str(ROOT/"src/secret_keeper/request_capture.py"),
                 "--set","secret_keeper_policy="+str(temp/"policy.json"),
                 "--set","request_log="+(str(temp/"audit.jsonl") if log_enabled else "")]
        try:
            with (temp/"proxy.log").open("wb") as log:
                proc=subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT)
                deadline=time.monotonic()+20
                while True:
                    h.require(proc.poll() is None,"proxy exited")
                    try:
                        with socket.create_connection(("127.0.0.1",port),timeout=.3):break
                    except OSError:
                        h.require(time.monotonic()<deadline,"startup timeout");time.sleep(.1)
                payload=json.dumps({"message":h.CANARY}).encode()
                good=b'{"message":"hello"}'
                status,_=h.post(port,upstream.server_port,good)
                h.require(status==200 and good in upstream.snapshot("http"),"HTTP positive control failed")
                blocked=mode in ("block","conflict")
                status,_=h.post(port,upstream.server_port,payload)
                h.require(status==(422 if blocked else 200),"HTTP decision incorrect")
                h.require((payload in upstream.snapshot("http"))== (not blocked),"HTTP upstream receipt incorrect")
                if blocked:
                    h.ws_checks(port,upstream.server_port,upstream,h.CANARY.encode(),mode)
                else:
                    with socket.create_connection(("127.0.0.1",port),timeout=8) as sock:
                        stream=sock.makefile("rb")
                        try:
                            import base64,os,hashlib
                            key=base64.b64encode(os.urandom(16)).decode()
                            req=(f"GET http://127.0.0.1:{upstream.server_port}/ws HTTP/1.1\r\nHost: 127.0.0.1:{upstream.server_port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n")
                            sock.sendall(req.encode());h.require(b" 101 " in stream.readline(),"WS upgrade failed")
                            while True:
                                line=stream.readline();h.require(bool(line),"incomplete upgrade")
                                if line==b"\r\n":break
                            for message in (b"hello-before",h.CANARY.encode(),b"hello-after"):
                                sock.sendall(h.frame(message,masked=True))
                                h.require(h.read_frame(stream)==(1,message),"WS allowed echo missing")
                            h.require(h.CANARY.encode() in upstream.snapshot("websocket"),"WS forwarding receipt missing")
                            sock.sendall(h.frame(b"",masked=True,opcode=8))
                        finally:stream.close()
                if log_enabled:
                    records=[json.loads(line) for line in (temp/"audit.jsonl").read_text().splitlines()]
                    for transport in ("http","websocket"):
                        selected=[r for r in records if r.get("transport")==transport]
                        if mode=="disabled":
                            h.require(all(r["decision"]=="ALLOW" for r in selected),"disabled rule logged a match")
                        else:
                            expected="AUDIT" if mode in ("audit","conflict") else "BLOCK"
                            final="BLOCK" if blocked else "ALLOW"
                            h.require(any(r["decision"]==expected and r.get("final_decision")==final for r in selected),"audit semantics incorrect")
                            if mode=="conflict":h.require(any(r["decision"]=="BLOCK" for r in selected),"conflict block missing")
                print("PASS",mode,"HTTP + WebSocket; audit="+str(log_enabled),flush=True)
        except Exception:
            print((temp/"proxy.log").read_text(errors="replace"),file=sys.stderr)
            raise
        finally:
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:proc.wait(timeout=5)
                except subprocess.TimeoutExpired:proc.kill();proc.wait()
            upstream.shutdown();upstream.server_close();thread.join(timeout=3)


if __name__=="__main__":
    try:
        for enabled in (True,False):
            for mode in ("block","audit","disabled","conflict"):check(mode,enabled)
        print("PASS: 16 schema-2 transport/mode checks. HTTP/WS only; client UX unchanged.")
    except Exception as error:
        print("FAIL:",str(error),file=sys.stderr);sys.exit(1)
