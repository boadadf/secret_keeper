"""Opt-in sensitive JSONL capture plus human-readable companion."""
import base64
import importlib.util
import json
import logging
import os
from pathlib import Path
from datetime import datetime,timezone

_spec=importlib.util.spec_from_file_location("secret_keeper_readable",Path(__file__).with_name("readable_capture.py"))
_fmt=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(_fmt)
LOG=logging.getLogger("secret_keeper.capture")

class PayloadCapture:
    def __init__(self):
        self.enabled=False;self.path=None;self.readable_path=None
        self.limit=1048576;self.file_limit=16777216;self.backups=3;self.ready=False
    def load(self,loader):
        loader.add_option("capture_mode",str,"off","Sensitive outbound capture: off/full")
        loader.add_option("capture_file",str,"","Dedicated private JSONL path")
        loader.add_option("capture_max_payload_bytes",int,1048576,"Bytes per captured representation")
        loader.add_option("capture_max_file_bytes",int,16777216,"Per-file rotation limit")
        loader.add_option("capture_backups",int,3,"Rotated backups per output (0-10)")
        loader.add_option("capture_readable",bool,True,"Also write readable text when full capture is enabled")
        loader.add_option("capture_readable_file",str,"","Optional readable path; defaults to capture_file plus .txt")
    def configure(self,options):
        self.ready=True;self.enabled=False;self.readable_path=None
        mode=getattr(options,"capture_mode","off")
        if mode not in ("off","full"):
            LOG.error("Secret Keeper CAPTURE ERROR: mode must be off/full; capture disabled");return
        if mode=="off":return
        try:
            name=getattr(options,"capture_file","")
            if not name:raise ValueError("capture path required")
            path=Path(name).expanduser().absolute()
            audit=getattr(options,"request_log","")
            paths=[path]
            enabled=getattr(options,"capture_readable",True)
            if type(enabled) is not bool:raise ValueError("readable flag must be boolean")
            readable_name=getattr(options,"capture_readable_file","")
            readable_path=Path(readable_name).expanduser().absolute() if readable_name else Path(str(path)+".txt")
            if enabled:paths.append(readable_path)
            if len({p.resolve() for p in paths})!=len(paths):raise ValueError("capture paths must differ")
            if audit and any(p.resolve()==Path(audit).expanduser().resolve() for p in paths):raise ValueError("audit/capture paths must differ")
            limit=getattr(options,"capture_max_payload_bytes",1048576)
            file_limit=getattr(options,"capture_max_file_bytes",16777216)
            backups=getattr(options,"capture_backups",3)
            if type(limit) is not int or not 1024<=limit<=10485760:raise ValueError("payload limit")
            if type(file_limit) is not int or not 8*limit+65536<=file_limit<=536870912:raise ValueError("file limit")
            if type(backups) is not int or not 0<=backups<=10:raise ValueError("backups")
            for p in paths:
                p.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
                if p.is_symlink() or (p.exists() and not p.is_file()):raise ValueError("unsafe path")
            self.path=path;self.readable_path=readable_path if enabled else None
            self.limit=limit;self.file_limit=file_limit;self.backups=backups;self.enabled=True
            LOG.error("Secret Keeper FULL CAPTURE ACTIVE: payload files may contain secrets; readable output=%s",bool(self.readable_path))
        except (OSError,ValueError,TypeError):LOG.error("Secret Keeper CAPTURE ERROR: invalid/unwritable config; capture disabled; enforcement unchanged")
    def rotate(self,path=None):
        path=path or self.path
        if self.backups==0:path.unlink(missing_ok=True);return
        Path(str(path)+"."+str(self.backups)).unlink(missing_ok=True)
        for index in range(self.backups-1,0,-1):
            old=Path(str(path)+"."+str(index))
            if old.exists():os.replace(old,Path(str(path)+"."+str(index+1)))
        if path.exists():os.replace(path,Path(str(path)+".1"))
    def append(self,path,data,label):
        try:
            if len(data)>self.file_limit or path.is_symlink():raise ValueError("output limit/path")
            if path.exists() and path.stat().st_size+len(data)>self.file_limit:self.rotate(path)
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
            with os.fdopen(fd,"ab") as out:out.write(data)
        except (OSError,ValueError):LOG.error("Secret Keeper CAPTURE WRITE FAILED (%s): record not guaranteed saved; enforcement unchanged",label)
    def write(self,flow,transport,matches,raw=None,text=None,message_index=None):
        if not self.enabled:return
        record={"schema_version":1,"timestamp":datetime.now(timezone.utc).isoformat(),"flow_id":flow.id,"transport":transport,
                "direction":"client_to_server","capture_stage":"attempted_outbound",
                "final_decision":"BLOCK" if any(m.get("action")=="block" for m in matches) else "ALLOW",
                "matched_rule_ids":[m["rule_id"] for m in matches],"body_available":raw is not None,
                "raw_body_bytes":len(raw) if raw is not None else None,"payload_limit_bytes":self.limit}
        if message_index is not None:record["message_index"]=message_index
        if raw is not None:
            record["body_raw_base64"]=base64.b64encode(raw[:self.limit]).decode("ascii");record["raw_truncated"]=len(raw)>self.limit
        if text is not None:
            encoded=text.encode("utf-8");record["body_text"]=encoded[:self.limit].decode("utf-8",errors="ignore")
            record["text_truncated"]=len(encoded)>self.limit;record["decoded_text_bytes"]=len(encoded)
        self.append(self.path,(json.dumps(record,ensure_ascii=True)+"\n").encode(),"JSONL")
        if self.readable_path:
            try:pretty=_fmt.readable(record,max_chars=min(self.file_limit-1024,max(2097152,8*self.limit))).encode("utf-8")
            except (ValueError,TypeError,RecursionError):
                LOG.error("Secret Keeper readable formatting failed; inspect JSONL");return
            self.append(self.readable_path,pretty,"readable")
