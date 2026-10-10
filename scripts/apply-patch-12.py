from pathlib import Path
import ast
import sys
root=Path(__file__).resolve().parents[1]
target=root/"src/secret_keeper/request_capture.py"
source=target.read_text(encoding="utf-8")
if "secret_keeper_response_provenance" in source:
    print("Patch 12 already applied.");sys.exit(0)
changes=[('_capture=adjacent("secret_keeper_payload_capture","payload_capture.py")', '_capture=adjacent("secret_keeper_payload_capture","payload_capture.py")\n_provenance=adjacent("secret_keeper_response_provenance","response_provenance.py")'), ('self.policy=None;self.policy_error=True;self.capture=_capture.PayloadCapture()', 'self.policy=None;self.policy_error=True;self.capture=_capture.PayloadCapture();self.provenance=_provenance.ResponseProvenance()'), ('self.capture.load(loader)', 'self.capture.load(loader)\n        loader.add_option("sk_allow_verified_assistant_credentials",bool,True,"Exempt credential-assignment matches only in verified previous model output")'), ('def responseheaders(self,flow:http.HTTPFlow):flow.response.stream=True', 'def responseheaders(self,flow:http.HTTPFlow):\n        if getattr(ctx.options,"sk_allow_verified_assistant_credentials",True):self.provenance.responseheaders(flow)\n        else:flow.response.stream=True'), ('def evaluate(self,text):', 'def evaluate(self,text,flow=None):'), ('return inspect(self.policy,text)', 'matches=inspect(self.policy,text)\n        if flow is None or not getattr(ctx.options,"sk_allow_verified_assistant_credentials",True):return matches\n        if not any(m.get("detector")=="credential_assignment" for m in matches):return matches\n        sanitized,count=self.provenance.sanitized(flow,text)\n        if not count:return matches\n        subset=dict(self.policy,rules=[r for r in self.policy["rules"] if r.get("detector")=="credential_assignment"])\n        remaining=inspect(subset,sanitized)\n        original=[m for m in matches if m.get("detector")=="credential_assignment"]\n        if len(remaining)<len(original):LOG.warning("Secret Keeper PROVENANCE EXEMPTION: verified model output excluded from credential-assignment checks; other rules remain enforced")\n        return [m for m in matches if m.get("detector")!="credential_assignment"]+remaining'), ('matches=self.evaluate(text)', 'matches=self.evaluate(text,flow)')]
for old,new in changes:
    if old not in source:raise SystemExit("ERROR: unexpected addon layout; no changes written. Missing: "+old[:80])
    source=source.replace(old,new)
ast.parse(source)
backup=target.with_name("request_capture.py.before-patch-12")
if backup.exists():raise SystemExit("ERROR: backup exists; no changes written")
backup.write_bytes(target.read_bytes())
target.write_text(source,encoding="utf-8")
print("Patch 12 applied. Restart proxy. Backup: request_capture.py.before-patch-12")
