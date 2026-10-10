"""Readable local rendering of sensitive captures; no network calls."""
import base64
import json
import re
import textwrap


def safe(value):
    text=str(value)
    return re.sub(r"[\x00-\x08\x0b-\x1f\x7f]",lambda m:"\\x%02x"%ord(m.group()),text)


def readable(record,width=100,max_chars=2097152):
    width=max(40,min(width,160));lines=[];used=0;omitted=False;nodes=0
    def add(value="",indent=0):
        nonlocal used,omitted
        if omitted:return
        prefix=" "*min(indent,24)
        for physical in safe(value).split("\n"):
            wrapped=textwrap.wrap(physical,width=max(16,width-len(prefix)),replace_whitespace=False,drop_whitespace=False,break_long_words=True,break_on_hyphens=False) or [""]
            for segment in wrapped:
                line=prefix+segment
                if used+len(line)+1>max_chars:
                    omitted=True;lines.append("[Readable display limit reached; inspect JSONL for remaining captured data.]");return
                lines.append(line);used+=len(line)+1
    def tree(value,indent=0,depth=0):
        nonlocal nodes
        nodes+=1
        if omitted:return
        if depth>24 or nodes>10000:
            add("[Structure display limit reached; see JSONL.]",indent);return
        if isinstance(value,dict):
            if not value:add("{}",indent)
            for key,item in value.items():
                add(str(key)+":",indent);tree(item,indent+2,depth+1)
                if omitted:return
        elif isinstance(value,list):
            if not value:add("[]",indent)
            for i,item in enumerate(value):
                add("["+str(i)+"]",indent);tree(item,indent+2,depth+1)
                if omitted:return
        elif isinstance(value,str):
            if value.lstrip().startswith(("{","[")) and len(value)<=2097152:
                try:nested=json.loads(value)
                except (ValueError,RecursionError):nested=None
                if isinstance(nested,(dict,list)):
                    add("(JSON inside a text field)",indent);tree(nested,indent+2,depth+1);return
            add(value,indent)
        else:add(json.dumps(value,ensure_ascii=False),indent)
    add("="*width)
    add("OUTGOING PAYLOAD — "+str(record.get("transport","unknown")).upper()+" — "+str(record.get("final_decision","UNKNOWN")))
    add("Time: "+str(record.get("timestamp","unknown")))
    add("Flow: "+str(record.get("flow_id","unknown")))
    if "destination" in record:add("Destination: "+str(record["destination"]))
    add("Stage: attempted outbound content; ALLOW does not prove destination receipt.")
    add("Rules: "+(", ".join(str(x) for x in record.get("matched_rule_ids",[])) or "none"))
    if "message_index" in record:add("WebSocket message index: "+str(record["message_index"]))
    add("Original raw bytes: "+str(record.get("raw_body_bytes","unknown")))
    if record.get("raw_truncated") or record.get("text_truncated"):
        add("WARNING: captured content was truncated by the capture size limit.")
    add();add("CONTENT:")
    text=record.get("body_text")
    if text is None and "body_raw_base64" in record:
        try:
            raw=base64.b64decode(record["body_raw_base64"],validate=True)
            try:text=raw.decode("utf-8",errors="strict")
            except UnicodeError:
                add("[Binary/compressed or non-UTF-8 body: "+str(len(raw))+" captured bytes.]")
                add("Raw bytes are stored as Base64 in JSONL; no huge Base64 dump shown here.")
        except (ValueError,TypeError):add("[Raw payload could not be decoded.]")
    if text is not None:
        try:value=json.loads(text)
        except (ValueError,RecursionError):value=text
        tree(value,2)
    elif not record.get("body_available",True):add("[Body unavailable.]")
    add();add("="*width);add()
    return "\n".join(lines)+"\n"
