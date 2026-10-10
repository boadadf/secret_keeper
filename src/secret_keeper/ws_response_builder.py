"""Local rejection text and experimental Copilot WebSocket completion."""
import copy
import time
import uuid
NOTICE = 'SecretKeeper blocked an outbound request that matched your data-protection policy. The blocked request was not forwarded. Retry with less context or start a new session if the same block repeats. Advanced details are available in the local proxy audit log.'

def build_events(request):
    rid = "resp_secretkeeper_" + uuid.uuid4().hex
    iid = "msg_secretkeeper_" + uuid.uuid4().hex
    part = {"type":"output_text", "text":NOTICE, "annotations":[], "logprobs":[]}
    item = {"id":iid, "type":"message", "role":"assistant", "phase":"final_answer", "status":"completed", "content":[part]}
    response = {"id":rid, "object":"response", "created_at":int(time.time()), "status":"in_progress", "error":None, "incomplete_details":None, "output":[], "model":request.get("model", ""), "store":False, "usage":None}
    events = [
        {"type":"response.created", "response":copy.deepcopy(response)},
        {"type":"response.in_progress", "response":copy.deepcopy(response)},
        {"type":"response.output_item.added", "output_index":0, "item":dict(item, status="in_progress", content=[])},
        {"type":"response.content_part.added", "output_index":0, "item_id":iid, "content_index":0, "part":dict(part, text="")},
        {"type":"response.output_text.delta", "output_index":0, "item_id":iid, "content_index":0, "delta":NOTICE, "logprobs":[]},
        {"type":"response.output_text.done", "output_index":0, "item_id":iid, "content_index":0, "text":NOTICE, "logprobs":[]},
        {"type":"response.content_part.done", "output_index":0, "item_id":iid, "content_index":0, "part":copy.deepcopy(part)},
        {"type":"response.output_item.done", "output_index":0, "item":copy.deepcopy(item)},
    ]
    response.update(status="completed", completed_at=int(time.time()), output=[copy.deepcopy(item)])
    events.append({"type":"response.completed", "response":response})
    for number, event in enumerate(events):
        event["sequence_number"] = number
        if "stream_id" in request: event["stream_id"] = request["stream_id"]
    return events
