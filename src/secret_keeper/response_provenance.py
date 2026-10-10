import hashlib
import json
import logging
import time
from collections import OrderedDict
LOG=logging.getLogger("secret_keeper.provenance")
MAX_BYTES=2097152

def digest(value):return hashlib.sha256(value.encode("utf-8")).hexdigest()
def content_text(content):
    if isinstance(content,str):return content
    if not isinstance(content,list):return None
    parts=[]
    for part in content:
        if not isinstance(part,dict) or part.get("type") not in ("text","input_text","output_text") or not isinstance(part.get("text"),str):return None
        parts.append(part["text"])
    return "".join(parts) if parts else None

def messages(body):
    if not isinstance(body,dict):return []
    value=body.get("messages",body.get("input"))
    return value if isinstance(value,list) else []

def user_anchors(body):
    return tuple(digest(text) for msg in messages(body) if isinstance(msg,dict) and msg.get("role")=="user" and (text:=content_text(msg.get("content"))) is not None)

def scope(flow):
    auth=getattr(flow.request,"headers",{}).get("authorization","")
    if not auth:return None
    return digest(str(flow.request.host).lower()+"\n"+auth)

def answer_text(body):
    if not isinstance(body,dict):return None
    if isinstance(body.get("choices"),list) and len(body["choices"])==1:
        message=body["choices"][0].get("message",{})
        if isinstance(message,dict) and message.get("role")=="assistant":return content_text(message.get("content"))
    if body.get("object")=="response" and body.get("status")=="completed":
        parts=[]
        for item in body.get("output",[]):
            if isinstance(item,dict) and item.get("type")=="message" and item.get("role")=="assistant":
                text=content_text(item.get("content"))
                if text is None:return None
                parts.append(text)
        return "".join(parts) if parts else None
    if body.get("type")=="message" and body.get("role")=="assistant" and body.get("stop_reason"):
        return content_text(body.get("content"))
    return None

def sse_answer(raw):
    parts=[];complete=False;final=None
    for event in raw.replace("\r\n","\n").split("\n\n"):
        data="\n".join(line[5:].lstrip(" ") for line in event.split("\n") if line.startswith("data:"))
        if not data:continue
        if data=="[DONE]":complete=True;continue
        try:obj=json.loads(data)
        except ValueError:return None
        if not isinstance(obj,dict):return None
        if "error" in obj or obj.get("type") in ("error","response.failed","response.incomplete"):return None
        if isinstance(obj.get("choices"),list):
            if len(obj["choices"])>1:return None
            for choice in obj["choices"]:
                if choice.get("index",0)!=0:return None
                text=choice.get("delta",{}).get("content")
                if isinstance(text,str):parts.append(text)
                if choice.get("finish_reason") is not None:complete=True
        elif obj.get("type")=="response.output_text.delta":
            if isinstance(obj.get("delta"),str):parts.append(obj["delta"])
        elif obj.get("type")=="response.completed":
            final=answer_text(obj.get("response"));complete=final is not None
        elif obj.get("type")=="content_block_delta":
            delta=obj.get("delta",{})
            if delta.get("type")=="text_delta" and isinstance(delta.get("text"),str):parts.append(delta["text"])
        elif obj.get("type")=="message_stop":complete=True
    if final is not None:return final
    return "".join(parts) if complete and parts else None

class ResponseProvenance:
    def __init__(self):self.entries=OrderedDict()
    def remember(self,key,anchors,text):
        if not key or not anchors or not text or len(text.encode("utf-8"))>MAX_BYTES:return
        self.entries[(key,digest(text))]=(time.monotonic(),anchors)
        self.entries.move_to_end((key,digest(text)))
        while len(self.entries)>256:self.entries.popitem(last=False)
        LOG.info("Secret Keeper recorded completed model-output provenance (content not logged)")
    def sanitized(self,flow,text):
        key=scope(flow)
        if not key:return None,0
        try:body=json.loads(text)
        except (ValueError,RecursionError):return None,0
        history=[];count=0
        for msg in messages(body):
            if not isinstance(msg,dict):continue
            value=content_text(msg.get("content"))
            if msg.get("role")=="user" and value is not None:history.append(digest(value))
            if msg.get("role")!="assistant" or value is None:continue
            entry=self.entries.get((key,digest(value)))
            if not entry:continue
            stamp,anchors=entry
            if time.monotonic()-stamp>1800:continue
            if tuple(history[:len(anchors)])!=anchors:continue
            msg["content"]="[verified prior output omitted for credential-assignment inspection only]";count+=1
        return (json.dumps(body,ensure_ascii=False),count) if count else (None,0)
    def responseheaders(self,flow):
        flow.response.stream=True
        if not scope(flow) or not 200<=flow.response.status_code<300:return
        if flow.response.headers.get("content-encoding","").lower() not in ("","identity"):
            LOG.info("Secret Keeper provenance unavailable for encoded response");return
        ct=flow.response.headers.get("content-type","").lower()
        if "text/event-stream" not in ct and "application/json" not in ct:return
        try:anchors=user_anchors(json.loads(flow.request.get_text(strict=True)))
        except (ValueError,TypeError,RecursionError):return
        if not anchors:return
        key=scope(flow);buffer=bytearray();overflow=False
        def observe(chunk):
            nonlocal overflow
            if chunk:
                if not overflow and len(buffer)+len(chunk)<=MAX_BYTES:buffer.extend(chunk)
                else:overflow=True;buffer.clear()
            elif not overflow:
                try:
                    text=buffer.decode("utf-8",errors="strict")
                    output=sse_answer(text) if "text/event-stream" in ct else answer_text(json.loads(text))
                    self.remember(key,anchors,output)
                except (ValueError,TypeError,RecursionError,KeyError,AttributeError):
                    LOG.info("Secret Keeper provenance unavailable for response format")
                buffer.clear()
            return chunk
        flow.response.stream=observe
