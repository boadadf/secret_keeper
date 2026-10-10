"""mitmproxy entry point: deterministic rules plus opt-in payload capture."""
import importlib.util
import json
import logging
import os
from datetime import datetime,timezone
from pathlib import Path
from mitmproxy import ctx,http

def adjacent(name,filename):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(filename))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

_rules=adjacent("secret_keeper_local_rules","rules.py")
_reply=adjacent("secret_keeper_reply","ws_response_builder.py")
_capture=adjacent("secret_keeper_payload_capture","payload_capture.py")
validate_policy=_rules.validate_policy
inspect=_rules.inspect
CANARY=_rules.CANARY
DEFAULT_POLICY=Path(__file__).resolve().parents[2]/"config"/"secret-keeper-policy.json"
LOG=logging.getLogger("secret_keeper.proxy")

class RequestCapture:
    def __init__(self):
        self.policy=None;self.policy_error=True;self.capture=_capture.PayloadCapture()
        self.ws_active={};self.ws_local_ids={}
    def load(self,loader):
        loader.add_option("request_log",str,"","Metadata-only JSONL audit path")
        loader.add_option("secret_keeper_policy",str,str(DEFAULT_POLICY),"Private JSON policy path")
        self.capture.load(loader)
        loader.add_option("secret_keeper_ws_client",str,"copilot","WebSocket reply format: copilot/none")
    def configure(self,updated):
        if not self.capture.ready or set(updated)&{"capture_mode","capture_file","capture_max_payload_bytes","capture_max_file_bytes","capture_backups","request_log"}:
            self.capture.configure(ctx.options)
        if self.policy is None or "secret_keeper_policy" in updated:
            try:
                path=Path(ctx.options.secret_keeper_policy)
                if path.stat().st_size>2097152:raise ValueError("policy size")
                self.policy=validate_policy(json.loads(path.read_text(encoding="utf-8")))
                self.policy_error=False
                LOG.info("Secret Keeper loaded schema %s, %s rules",self.policy["source_schema_version"],len(self.policy["rules"]))
            except (OSError,ValueError,TypeError,RecursionError):
                self.policy=None;self.policy_error=True
                LOG.error("Secret Keeper POLICY ERROR: fix private policy and restart; requests will reject")
    def requestheaders(self,flow:http.HTTPFlow):flow.request.stream=False
    def responseheaders(self,flow:http.HTTPFlow):flow.response.stream=True
    def evaluate(self,text):
        if self.policy_error or self.policy is None:return [{"rule_id":"policy_error","action":"block","location":"policy"}]
        return inspect(self.policy,text)
    def audit(self,flow,transport,decision,details=None):
        record={"schema_version":6,"timestamp":datetime.now(timezone.utc).isoformat(),"flow_id":flow.id,"transport":transport,"direction":"client_to_server","decision":decision}
        record.update(details or {})
        if decision in ("BLOCK","AUDIT"):LOG.error("Secret Keeper %s %s",decision,json.dumps(record,ensure_ascii=True))
        if not ctx.options.request_log:return
        try:
            path=Path(ctx.options.request_log).expanduser();path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
            with os.fdopen(fd,"a",encoding="utf-8") as stream:stream.write(json.dumps(record,ensure_ascii=True)+"\n")
        except OSError:LOG.error("Secret Keeper audit write failed")
    def record_matches(self,flow,transport,matches):
        blocked=any(m["action"]=="block" for m in matches)
        for match in matches:self.audit(flow,transport,"BLOCK" if match["action"]=="block" else "AUDIT",dict(match,final_decision="BLOCK" if blocked else "ALLOW"))
        if not blocked:self.audit(flow,transport,"ALLOW")
    def failure(self,rule):return [{"rule_id":rule,"action":"block","location":"body"}]
    def request(self,flow:http.HTTPFlow):
        raw=None;text=None
        try:
            raw=flow.request.raw_content
            if raw is None:matches=self.failure("body_unavailable")
            else:
                text=flow.request.get_text(strict=True) or ""
                matches=self.evaluate(text)
        except _rules.InspectionLimit:matches=self.failure("inspection_limit")
        except (ValueError,RecursionError):matches=self.failure("inspection_error")
        block=next((m for m in matches if m["action"]=="block"),None)
        if block:
            flow.response=http.Response.make(422,json.dumps({"error":{"type":"policy_violation","code":"secret_keeper_blocked","message":_reply.NOTICE,"rule_id":block["rule_id"],"reference":flow.id}}).encode(),{"Content-Type":"application/json","Cache-Control":"no-store","X-SecretKeeper-Blocked":"true"})
            LOG.warning("SecretKeeper prevented an outbound disclosure. Retry with less context or start a new session. Details: rule=%s reference=%s",block["rule_id"],flow.id)
        self.record_matches(flow,"http",matches)
        self.capture.write(flow,"http",matches,raw,text)
    def websocket_end(self, flow):
        self.ws_active.pop(flow.id, None)
        self.ws_local_ids.pop(flow.id, None)
    def ws_stop(self, flow, reason):
        self.audit(flow,"websocket","BLOCK",{"rule_id":reason,"action":"block","location":"adapter","final_decision":"BLOCK","reply":"connection_terminated"})
        flow.kill()
    def websocket_message(self, flow):
        if not flow.websocket or not flow.websocket.messages:return
        message=flow.websocket.messages[-1]
        if getattr(message,"injected",False):return
        text=None;payload=None
        try:
            text=message.content.decode("utf-8",errors="strict")
            parsed=json.loads(text)
            if isinstance(parsed,dict):payload=parsed
        except (ValueError,RecursionError):pass
        if not message.from_client:
            if payload and payload.get("type") in ("response.completed","response.failed","response.incomplete"):
                self.ws_active[flow.id]=max(0,self.ws_active.get(flow.id,0)-1)
            return
        try:matches=self.evaluate(text) if text is not None else self.failure("inspection_error")
        except _rules.InspectionLimit:matches=self.failure("inspection_limit")
        except (ValueError,RecursionError):matches=self.failure("inspection_error")
        previous=payload.get("previous_response_id") if payload else None
        if isinstance(previous,str) and previous in self.ws_local_ids.get(flow.id,set()):
            matches.append({"rule_id":"local_response_continuation","action":"block","location":"adapter"})
        blocked=any(m["action"]=="block" for m in matches)
        if blocked:message.drop()
        self.record_matches(flow,"websocket",matches)
        self.capture.write(flow,"websocket",matches,message.content,text,len(flow.websocket.messages)-1)
        if not blocked:
            if payload and payload.get("type")=="response.create":self.ws_active[flow.id]=self.ws_active.get(flow.id,0)+1
            return
        LOG.warning("SecretKeeper prevented an outbound disclosure. Retry with less context or start a new session. Reference=%s",flow.id)
        mode=getattr(ctx.options,"secret_keeper_ws_client","copilot")
        if mode=="none":
            self.ws_stop(flow,"ws_reply_disabled");return
        if mode!="copilot" or not payload or payload.get("type")!="response.create":
            self.ws_stop(flow,"ws_protocol_unsupported");return
        if self.ws_active.get(flow.id,0):
            self.ws_stop(flow,"ws_concurrent_response_unsupported");return
        try:
            ids=self.ws_local_ids.setdefault(flow.id,set())
            if len(ids)>=1024:self.ws_stop(flow,"ws_state_limit");return
            events=_reply.build_events(payload)
            ids.add(events[-1]["response"]["id"])
            for event in events:
                ctx.master.commands.call("inject.websocket",flow,True,json.dumps(event,ensure_ascii=False,separators=(",",":")).encode("utf-8"))
            self.audit(flow,"websocket","BLOCK",{"rule_id":"ws_local_reply","action":"block","location":"adapter","final_decision":"BLOCK","reply":"synthetic_completed","event_count":len(events)})
        except Exception:
            LOG.error("SecretKeeper WS notification failed; terminating blocked flow")
            flow.kill()

addons=[RequestCapture()]
