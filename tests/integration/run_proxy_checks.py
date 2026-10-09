"""Local real-proxy integration checks; standard library client/server only."""
import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
CANARY = "SECRET_KEEPER_CONFIDENTIAL_CANARY"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def exact(stream, length):
    data = b""
    while len(data) < length:
        part = stream.read(length - len(data))
        if not part:
            raise EOFError("connection ended")
        data += part
    return data


def frame(payload, masked=False, opcode=1):
    size = len(payload)
    prefix = bytes([128 | opcode])
    flag = 128 if masked else 0
    if size < 126:
        prefix += bytes([flag | size])
    elif size < 65536:
        prefix += bytes([flag | 126]) + struct.pack("!H", size)
    else:
        prefix += bytes([flag | 127]) + struct.pack("!Q", size)
    if masked:
        mask = os.urandom(4)
        return prefix + mask + bytes(v ^ mask[i % 4] for i, v in enumerate(payload))
    return prefix + payload


def read_frame(stream):
    head = exact(stream, 2)
    size = head[1] & 127
    if size == 126:
        size = struct.unpack("!H", exact(stream, 2))[0]
    elif size == 127:
        size = struct.unpack("!Q", exact(stream, 8))[0]
    require(size <= 1024 * 1024, "test frame too large")
    mask = exact(stream, 4) if head[1] & 128 else None
    payload = exact(stream, size)
    if mask:
        payload = bytes(v ^ mask[i % 4] for i, v in enumerate(payload))
    return head[0] & 15, payload


class Upstream(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self):
        super().__init__(("127.0.0.1", 0), Handler)
        self.receipts = []
        self.lock = threading.Lock()

    def record(self, kind, payload):
        with self.lock:
            self.receipts.append((kind, payload))

    def snapshot(self, kind):
        with self.lock:
            return [payload for transport, payload in self.receipts if transport == kind]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *args):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.record("http", body)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"OK")
        self.wfile.flush()

    def do_GET(self):
        if self.headers.get("Upgrade", "").lower() != "websocket":
            self.send_error(400)
            return
        key = self.headers["Sec-WebSocket-Key"]
        accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        self.wfile.flush()
        self.connection.settimeout(10)
        self.close_connection = True
        try:
            while True:
                opcode, payload = read_frame(self.rfile)
                if opcode == 8:
                    return
                if opcode == 9:
                    self.wfile.write(frame(payload, opcode=10))
                elif opcode == 1:
                    self.server.record("websocket", payload)
                    self.wfile.write(frame(payload))
                else:
                    raise RuntimeError("unexpected test frame")
                self.wfile.flush()
        except (EOFError, OSError):
            return


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def post(proxy_port, upstream_port, body):
    conn = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=8)
    try:
        conn.request("POST", f"http://127.0.0.1:{upstream_port}/check", body,
                     {"Content-Type": "application/json", "Connection": "close"})
        response = conn.getresponse()
        content = response.read()
        return response.status, content
    finally:
        conn.close()


def ws_checks(proxy_port, upstream_port, upstream, blocked, label):
    before = ("hello-before-" + label).encode()
    after = ("hello-after-" + label).encode()
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=8) as sock:
        stream = sock.makefile("rb")
        try:
            key = base64.b64encode(os.urandom(16)).decode()
            request = (f"GET http://127.0.0.1:{upstream_port}/ws HTTP/1.1\r\n"
                       f"Host: 127.0.0.1:{upstream_port}\r\nUpgrade: websocket\r\n"
                       f"Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
                       f"Sec-WebSocket-Key: {key}\r\n\r\n")
            sock.sendall(request.encode())
            status = stream.readline()
            require(b" 101 " in status, "WebSocket upgrade failed: " + repr(status))
            headers = {}
            while True:
                line = stream.readline()
                require(bool(line), "incomplete upgrade")
                if line == b"\r\n":
                    break
                name, val = line.decode().split(":", 1)
                headers[name.lower()] = val.strip()
            expected = base64.b64encode(hashlib.sha1((key+GUID).encode()).digest()).decode()
            require(headers.get("sec-websocket-accept") == expected, "invalid upgrade acceptance")
            sock.sendall(frame(before, masked=True))
            require(read_frame(stream) == (1, before), "allowed before-message not echoed")
            sock.sendall(frame(blocked, masked=True))
            sock.sendall(frame(after, masked=True))
            require(read_frame(stream) == (1, after), "blocked content echoed OR after-message missing")
            require(blocked not in upstream.snapshot("websocket"), "blocked WebSocket payload reached upstream")
            require(before in upstream.snapshot("websocket") and after in upstream.snapshot("websocket"),
                    "WebSocket positive controls missing")
            sock.sendall(frame(b"", masked=True, opcode=8))
        finally:
            stream.close()


def run(args):
    addon = Path(args.addon).resolve()
    require(addon.is_file(), "addon file missing: " + str(addon))
    exe = Path(args.mitmdump).resolve() if args.mitmdump else Path(sys.executable).parent / ("mitmdump.exe" if os.name == "nt" else "mitmdump")
    require(exe.is_file(), "mitmdump executable missing: " + str(exe))
    blocked_cases = [("canary", CANARY), ("dictionary", "Northstar Manufacturing"),
                     ("credential", 'password = "Synthetic-Only-42"')]
    results = []
    for audit_enabled in (True, False):
        upstream = Upstream()
        thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        thread.start()
        proc = None
        with tempfile.TemporaryDirectory(prefix="secret-keeper-integration-") as directory:
            temp = Path(directory)
            policy = {"schema_version":1,"canary_enabled":True,"secrets_enabled":True,
                      "dictionary":[{"id":"test-customer-001","values":["Northstar Manufacturing"],"boundary":"whole_phrase"}]}
            (temp / "policy.json").write_text(json.dumps(policy), encoding="utf-8")
            port = free_port()
            audit = str(temp / "audit.jsonl") if audit_enabled else ""
            cmd = [str(exe),"--mode","regular","--listen-host","127.0.0.1","--listen-port",str(port),
                   "--set","confdir="+str(temp / "state"),"--set","connection_strategy=lazy",
                   "--set","termlog_verbosity=error","--set","flow_detail=0",
                   "-s",str(addon),"--set","secret_keeper_policy="+str(temp / "policy.json"),
                   "--set","request_log="+audit]
            try:
                with (temp / "proxy.log").open("wb") as log:
                    proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT)
                    deadline = time.monotonic() + 20
                    while True:
                        require(proc.poll() is None, "proxy exited during startup")
                        try:
                            with socket.create_connection(("127.0.0.1", port), timeout=.3):
                                break
                        except OSError:
                            require(time.monotonic() < deadline, "proxy startup timed out")
                            time.sleep(.1)
                    for name, text in blocked_cases:
                        good = json.dumps({"message":"hello-"+name}).encode()
                        bad = json.dumps({"message":text}).encode()
                        status, _ = post(port, upstream.server_port, good)
                        require(status == 200 and good in upstream.snapshot("http"), "HTTP allow control failed")
                        status, body = post(port, upstream.server_port, bad)
                        require(status == 422 and b"secret_keeper_blocked" in body, "HTTP reject failed")
                        status, _ = post(port, upstream.server_port, good+b" ")
                        require(status == 200, "HTTP after-control failed")
                        require(bad not in upstream.snapshot("http"), "blocked HTTP payload reached upstream")
                        ws_checks(port, upstream.server_port, upstream, text.encode(), name)
                        results.append({"rule":name,"audit_enabled":audit_enabled,"http":"PASS","websocket":"PASS"})
                        print("PASS",name,"HTTP + WebSocket; audit="+str(audit_enabled),flush=True)
                    if audit_enabled:
                        records = [json.loads(line) for line in (temp / "audit.jsonl").read_text().splitlines()]
                        for transport in ("http","websocket"):
                            for rule in ("test_canary","dictionary","credential_assignment"):
                                require(any(r.get("transport")==transport and r.get("rule_id")==rule and r.get("decision")=="BLOCK" for r in records),
                                        "expected audit decision missing: "+transport+" "+rule)
                    else:
                        require(not (temp / "audit.jsonl").exists(), "audit file created while disabled")
            except Exception:
                if proc is not None and proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill(); proc.wait()
                print("Proxy diagnostic output:\n"+(temp / "proxy.log").read_text(errors="replace"),file=sys.stderr)
                raise
            finally:
                if proc is not None and proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill(); proc.wait()
                upstream.shutdown()
                upstream.server_close()
                thread.join(timeout=3)
    print("PASS: 12 transport/rule checks across audit-enabled and audit-disabled runs.")
    print("Scope: local HTTP/WS text messages; HTTPS/WSS, fragmentation, Copilot UX not covered.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--addon", default="src/secret_keeper/request_capture.py")
    parser.add_argument("--mitmdump")
    try:
        run(parser.parse_args())
    except Exception as exc:
        print("FAIL:",str(exc),file=sys.stderr)
        sys.exit(1)
