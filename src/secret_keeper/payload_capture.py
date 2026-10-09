"""Opt-in sensitive payload capture. No effect on enforcement decisions."""
import base64
import json
import logging
import os
from pathlib import Path
from datetime import datetime,timezone

LOG=logging.getLogger("secret_keeper.capture")

class PayloadCapture:
    def __init__(self):
        self.enabled=False
        self.path=None
        self.limit=1048576
        self.file_limit=16777216
        self.backups=3
        self.ready=False

    def load(self,loader):
        loader.add_option("capture_mode",str,"off","Sensitive payload capture: off or full")
        loader.add_option("capture_file",str,"","Dedicated private JSONL capture path")
        loader.add_option("capture_max_payload_bytes",int,1048576,"Maximum bytes per captured body representation")
        loader.add_option("capture_max_file_bytes",int,16777216,"Rotate before exceeding this capture file size")
        loader.add_option("capture_backups",int,3,"Number of rotated capture backups (0-10)")

    def configure(self,options):
        self.ready=True;self.enabled=False
        mode=getattr(options,"capture_mode","off")
        if mode not in ("off","full"):
            LOG.error("Secret Keeper CAPTURE ERROR: mode must be off or full; capture disabled")
            return
        if mode=="off":return
        try:
            name=getattr(options,"capture_file","")
            if not name:raise ValueError("dedicated capture_file required")
            path=Path(name).expanduser().absolute()
            audit=getattr(options,"request_log","")
            if audit and path.resolve()==Path(audit).expanduser().resolve():raise ValueError("capture and audit paths must differ")
            limit=getattr(options,"capture_max_payload_bytes",1048576)
            file_limit=getattr(options,"capture_max_file_bytes",16777216)
            backups=getattr(options,"capture_backups",3)
            if type(limit) is not int or not 1024<=limit<=10485760:raise ValueError("payload limit invalid")
            if type(file_limit) is not int or not 8*limit+65536<=file_limit<=536870912:raise ValueError("file limit invalid for selected payload limit")
            if type(backups) is not int or not 0<=backups<=10:raise ValueError("backup count invalid")
            path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            if path.is_symlink():raise ValueError("capture file cannot be a symlink")
            if path.exists() and not path.is_file():raise ValueError("capture path must be a file")
            self.path=path;self.limit=limit;self.file_limit=file_limit;self.backups=backups;self.enabled=True
            LOG.error("Secret Keeper FULL CAPTURE ACTIVE: may store secrets; outbound bodies/messages only; capped payloads; protect and remove files after analysis")
        except (OSError,ValueError,TypeError):
            LOG.error("Secret Keeper CAPTURE ERROR: invalid/unwritable configuration; capture disabled; enforcement unchanged")

    def rotate(self):
        if self.backups==0:
            self.path.unlink(missing_ok=True)
            return
        oldest=Path(str(self.path)+"."+str(self.backups));oldest.unlink(missing_ok=True)
        for index in range(self.backups-1,0,-1):
            old=Path(str(self.path)+"."+str(index))
            if old.exists():os.replace(old,Path(str(self.path)+"."+str(index+1)))
        if self.path.exists():os.replace(self.path,Path(str(self.path)+".1"))

    def write(self,flow,transport,matches,raw=None,text=None,message_index=None):
        if not self.enabled:return
        blocked=any(m.get("action")=="block" for m in matches)
        record={"schema_version":1,"timestamp":datetime.now(timezone.utc).isoformat(),
                "flow_id":flow.id,"transport":transport,"direction":"client_to_server",
                "capture_stage":"attempted_outbound","final_decision":"BLOCK" if blocked else "ALLOW",
                "matched_rule_ids":[m["rule_id"] for m in matches],"body_available":raw is not None,
                "raw_body_bytes":len(raw) if raw is not None else None,"payload_limit_bytes":self.limit}
        if message_index is not None:record["message_index"]=message_index
        if raw is not None:
            record["body_raw_base64"]=base64.b64encode(raw[:self.limit]).decode("ascii")
            record["raw_truncated"]=len(raw)>self.limit
        if text is not None:
            encoded=text.encode("utf-8")
            record["body_text"]=encoded[:self.limit].decode("utf-8",errors="ignore")
            record["text_truncated"]=len(encoded)>self.limit
            record["decoded_text_bytes"]=len(encoded)
        try:
            encoded=(json.dumps(record,ensure_ascii=True)+"\n").encode("utf-8")
            if len(encoded)>self.file_limit:raise ValueError("record exceeds file budget")
            if self.path.is_symlink():raise ValueError("capture symlink")
            if self.path.exists() and self.path.stat().st_size+len(encoded)>self.file_limit:self.rotate()
            fd=os.open(self.path,os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
            with os.fdopen(fd,"ab") as stream:stream.write(encoded)
        except (OSError,ValueError):
            LOG.error("Secret Keeper CAPTURE WRITE FAILED: record not guaranteed saved; enforcement unchanged")
