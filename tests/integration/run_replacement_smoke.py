"""Real local HTTP proxy test. Run with the project's mitmproxy virtualenv."""
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT=Path(__file__).resolve().parents[2]
received=[]
class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body=self.rfile.read(int(self.headers.get("Content-Length","0")))
        received.append(body)
        self.send_response(200);self.send_header("Content-Length","2");self.end_headers();self.wfile.write(b"OK")
    def log_message(self,*args):pass

def port():
    with socket.socket() as s:s.bind(("127.0.0.1",0));return s.getsockname()[1]

def main():
    executable=Path(sys.executable).parent/("mitmdump.exe" if os.name=="nt" else "mitmdump")
    if not executable.is_file():raise RuntimeError("Run using the project's .venv Python; mitmdump is missing.")
    server=ThreadingHTTPServer(("127.0.0.1",0),Handler)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    proxy_port=port()
    with tempfile.TemporaryDirectory(prefix="secretkeeper-smoke-") as temp:
        state=Path(temp);policy=state/"policy.json"
        policy.write_text(json.dumps({"schema_version":2,"replacements":[{"id":"mask-customer","enabled":True,"find":"Customer AG","replace_with":"[CUSTOMER]","case_sensitive":False,"boundary":"whole_phrase"}],"rules":[{"id":"fallback-customer","type":"exact_text","enabled":True,"action":"block","value":"Customer AG"},{"id":"block-password","type":"builtin","enabled":True,"action":"block","detector":"credential_assignment"}]}))
        with (state/"proxy.log").open("wb") as log:
            process=subprocess.Popen([str(executable),"--listen-host","127.0.0.1","--listen-port",str(proxy_port),"--set",f"confdir={state/'ca'}","--set","flow_detail=0","-s",str(ROOT/"src/secret_keeper/request_capture.py"),"--set",f"secret_keeper_policy={policy}"],stdout=log,stderr=subprocess.STDOUT,cwd=ROOT)
            try:
                deadline=time.monotonic()+15
                while True:
                    if process.poll() is not None:raise RuntimeError((state/"proxy.log").read_text(errors="replace"))
                    try:
                        with socket.create_connection(("127.0.0.1",proxy_port),timeout=.2):break
                    except OSError:
                        if time.monotonic()>deadline:raise RuntimeError("Proxy readiness timed out: not proof of blocking")
                        time.sleep(.1)
                def send(obj):
                    body=json.dumps(obj).encode()
                    with socket.create_connection(("127.0.0.1",proxy_port),timeout=5) as sock:
                        destination=f"127.0.0.1:{server.server_port}"
                        head=f"POST http://{destination}/ HTTP/1.1\r\nHost: {destination}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                        sock.sendall(head+body)
                        response=http.client.HTTPResponse(sock);response.begin();status=response.status;response.read();return status
                assert send({"text":"hello"})==200
                assert len(received)==1
                assert send({"text":"# Customer: Customer AG"})==200
                assert json.loads(received[-1])["text"]=="# Customer: [CUSTOMER]"
                assert b"Customer AG" not in received[-1]
                count=len(received)
                assert send({"text": 'Customer AG password = "Synthetic-Only-42"'})==422
                assert len(received)==count
                assert send({"id":"Customer AG","text":"hello"})==422
                assert len(received)==count
                assert send({"text":"another clean request"})==200
                assert len(received)==count+1
                print("PASS: positive controls, actual upstream replacement, residual blocking and clean follow-up.")
            finally:
                process.terminate()
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.wait()
                server.shutdown();server.server_close()

if __name__=="__main__":main()
