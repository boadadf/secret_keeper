import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import pytest
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location("provenance_test",ROOT/"src/secret_keeper/response_provenance.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
ANSWER='Password: "synthetic-test-value"'
PROMPT="Explain passwords"

def flow(body=None,auth="Bearer synthetic",host="api.example.test",ct="application/json",status=200):
    body=body or {"messages":[{"role":"user","content":PROMPT}]}
    request=SimpleNamespace(headers={"authorization":auth},host=host,get_text=lambda strict:json.dumps(body))
    return SimpleNamespace(request=request,response=SimpleNamespace(status_code=status,headers={"content-type":ct},stream=None))

def history(answer=ANSWER,prompt=PROMPT,role="assistant"):
    return {"messages":[{"role":"user","content":prompt},{"role":role,"content":answer},{"role":"user","content":"Continue"}]}

def remember(obj):
    f=flow();obj.remember(m.scope(f),m.user_anchors(json.loads(f.request.get_text(True))),ANSWER)

@pytest.mark.parametrize("kind",["chat","responses","anthropic"])
def test_http_json_output(kind):
    obj=m.ResponseProvenance();f=flow();obj.responseheaders(f)
    if kind=="chat":body={"choices":[{"message":{"role":"assistant","content":ANSWER}}]}
    elif kind=="responses":body={"object":"response","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":ANSWER}]}]}
    else:body={"type":"message","role":"assistant","stop_reason":"end_turn","content":[{"type":"text","text":ANSWER}]}
    raw=json.dumps(body).encode();assert f.response.stream(raw)==raw;assert f.response.stream(b"")==b""
    clean,count=obj.sanitized(flow(history()),json.dumps(history()));assert count==1 and ANSWER not in json.loads(clean)["messages"][1]["content"]

@pytest.mark.parametrize("role",["user","tool","system"])
def test_other_roles_not_exempt(role):
    obj=m.ResponseProvenance();remember(obj);body=history(role=role)
    assert obj.sanitized(flow(body),json.dumps(body))==(None,0)

@pytest.mark.parametrize("variation",["auth","host","prompt","edited","unrecorded"])
def test_scope_and_exact_text(variation):
    obj=m.ResponseProvenance()
    if variation!="unrecorded":remember(obj)
    body=history(answer=ANSWER+"!" if variation=="edited" else ANSWER,prompt="Different" if variation=="prompt" else PROMPT)
    f=flow(body,auth="Bearer other" if variation=="auth" else "Bearer synthetic",host="other.example" if variation=="host" else "api.example.test")
    assert obj.sanitized(f,json.dumps(body))==(None,0)

def test_expiry(monkeypatch):
    obj=m.ResponseProvenance();remember(obj);monkeypatch.setattr(m.time,"monotonic",lambda:10**20)
    assert obj.sanitized(flow(history()),json.dumps(history()))==(None,0)

def test_cache_bound():
    obj=m.ResponseProvenance()
    for i in range(300):obj.remember("key",("anchor",),"answer"+str(i))
    assert len(obj.entries)==256

@pytest.mark.parametrize("kind",["chat","responses","anthropic"])
def test_sse_fragmented(kind):
    obj=m.ResponseProvenance();f=flow(ct="text/event-stream");obj.responseheaders(f)
    if kind=="chat":events=[{"choices":[{"index":0,"delta":{"content":ANSWER[:10]},"finish_reason":None}]},{"choices":[{"index":0,"delta":{"content":ANSWER[10:]},"finish_reason":"stop"}]}]
    elif kind=="responses":events=[{"type":"response.output_text.delta","delta":ANSWER},{"type":"response.completed","response":{"object":"response","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":ANSWER}]}]}}]
    else:events=[{"type":"content_block_delta","delta":{"type":"text_delta","text":ANSWER}},{"type":"message_stop"}]
    raw="".join("data: "+json.dumps(e)+"\n\n" for e in events).encode()
    for i in range(0,len(raw),7):assert f.response.stream(raw[i:i+7])==raw[i:i+7]
    f.response.stream(b"");assert obj.sanitized(flow(history()),json.dumps(history()))[1]==1

@pytest.mark.parametrize("status",[422,500])
def test_error_responses_not_recorded(status):
    obj=m.ResponseProvenance();f=flow(status=status);obj.responseheaders(f);assert f.response.stream is True and not obj.entries

def test_overflow_not_recorded():
    obj=m.ResponseProvenance();f=flow();obj.responseheaders(f);data=b"x"*(m.MAX_BYTES+1)
    assert f.response.stream(data)==data;f.response.stream(b"");assert not obj.entries

@pytest.mark.parametrize("text",['data: {"type":"error"}\n\n','data: bad\n\n','data: {"choices":[{"delta":{"content":"hi"}}]}\n\n'])
def test_failed_or_incomplete_sse_not_recorded(text):assert m.sse_answer(text) is None

def test_encoded_response_not_recorded():
    obj=m.ResponseProvenance();f=flow();f.response.headers["content-encoding"]="gzip";obj.responseheaders(f);assert f.response.stream is True

def test_no_auth_no_exemption():
    obj=m.ResponseProvenance();remember(obj);body=history();assert obj.sanitized(flow(body,auth=""),json.dumps(body))==(None,0)

def test_input_format():
    obj=m.ResponseProvenance();remember(obj);body={"input":history()["messages"]};assert obj.sanitized(flow(body),json.dumps(body))[1]==1
