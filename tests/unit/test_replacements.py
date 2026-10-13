import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import pytest
ROOT=Path(__file__).resolve().parents[2]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    obj=importlib.util.module_from_spec(spec);spec.loader.exec_module(obj);return obj
e=load("replacement_rules","src/secret_keeper/rules.py")
def repl(**kw):
    return dict(id="mask-customer",enabled=True,find="Customer AG",replace_with="[CUSTOMER]",case_sensitive=False,boundary="whole_phrase",**kw)
def policy(replacements=None,rules=None):
    return e.validate_policy({"schema_version":2,"rules":rules or [],"replacements":replacements if replacements is not None else [repl()]})
def block(value):return dict(id="block-test",type="exact_text",enabled=True,action="block",value=value)
@pytest.mark.parametrize("body,expected",[
    ("# Customer: Customer AG","# Customer: [CUSTOMER]"),
    ("Customer AG Customer AG","[CUSTOMER] [CUSTOMER]"),
    ("customer ag","[CUSTOMER]"),
    ("Customer AGX","Customer AGX"),
    ("XCustomer AG","XCustomer AG"),
    ("(Customer AG)","([CUSTOMER])"),
])
def test_plain(body,expected):assert e.replace_text(policy(),body)[0]==expected

def test_json_values_preserve_keys_and_identity():
    body=json.dumps({"Customer AG":"key unchanged","text":"Customer AG","id":"Customer AG","model":"Customer AG"})
    changed,details=e.replace_text(policy(),body);obj=json.loads(changed)
    assert obj=={"Customer AG":"key unchanged","text":"[CUSTOMER]","id":"Customer AG","model":"Customer AG"}
    assert details==[{"rule_id":"mask-customer","action":"replace","occurrences":1}]

def test_content_arrays():
    body=json.dumps({"messages":[{"role":"user","content":[{"type":"text","text":"Customer AG"},{"type":"text","text":"hello"}]}]})
    result=json.loads(e.replace_text(policy(),body)[0]);assert result["messages"][0]["content"][0]["text"]=="[CUSTOMER]"

def test_custom_field():
    p=policy([repl(fields=["customer"])]);obj=json.loads(e.replace_text(p,'{"customer":"Customer AG","text":"Customer AG"}')[0])
    assert obj=={"customer":"[CUSTOMER]","text":"Customer AG"}

def test_literal_backslashes():
    r=repl();r["replace_with"]=r"\1 literal"
    assert e.replace_text(policy([r]),"Customer AG")[0]==r"\1 literal"

def test_no_chaining():
    a=repl();a["replace_with"]="Beta"
    b=dict(a,id="second",find="Beta",replace_with="Gamma")
    assert e.replace_text(policy([a,b]),"Customer AG Beta")[0]=="Beta Gamma"

def test_longest_overlap():
    short=repl();short.update(id="short-name",find="Customer",replace_with="SHORT",boundary="substring")
    assert e.replace_text(policy([short,repl()]),"Customer AG")[0]=="[CUSTOMER]"

def test_case_sensitive():
    r=repl();r["case_sensitive"]=True
    assert e.replace_text(policy([r]),"customer ag")[0]=="customer ag"

def test_substring():
    r=repl();r["boundary"]="substring"
    assert e.replace_text(policy([r]),"XCustomer AGX")[0]=="X[CUSTOMER]X"

def test_disabled_preserves_bytes():
    r=repl();r["enabled"]=False
    text=' { "text" : "Customer AG" } '
    assert e.replace_text(policy([r]),text)==(text,[])

def test_old_policy_no_change():
    p=e.validate_policy({"schema_version":2,"rules":[]})
    assert e.replace_text(p,"Customer AG")==("Customer AG",[])

def test_empty_replacement():
    r=repl();r["replace_with"]=""
    assert e.replace_text(policy([r]),"Customer AG")[0]==""

def test_quotes_and_unicode():
    r=repl();r["replace_with"]='"匿名"'
    assert json.loads(e.replace_text(policy([r]),'{"text":"Customer AG"}')[0])["text"]=='"匿名"'

def test_embedded_json():
    text=json.dumps({"content":json.dumps({"text":"Customer AG","id":"Customer AG"})})
    result=json.loads(e.replace_text(policy(),text)[0]);nested=json.loads(result["content"])
    assert nested=={"text":"[CUSTOMER]","id":"Customer AG"}

def test_other_block_still_matches():
    p=policy(rules=[block("password")]);text,_=e.replace_text(p,"Customer AG password")
    assert e.inspect(p,text)[0]["action"]=="block"

def test_dictionary_removed_before_inspect():
    r=dict(id="customer-names",type="dictionary",enabled=True,action="block",matching=dict(e.MATCHING),entries=[{"id":"customer-001","values":["Customer AG"]}])
    p=policy(rules=[r]);text,_=e.replace_text(p,"Customer AG")
    assert not e.inspect(p,text)

@pytest.mark.parametrize("mutation",["empty_find","unknown","regex","bad_bool","duplicate","fields","id_conflict"])
def test_bad_settings(mutation):
    r=repl();rs=[r];blocks=[]
    if mutation=="empty_find":r["find"]=""
    elif mutation=="unknown":r["oops"]=True
    elif mutation=="regex":r["boundary"]="regex"
    elif mutation=="bad_bool":r["enabled"]="true"
    elif mutation=="duplicate":rs.append(dict(r))
    elif mutation=="fields":r["fields"]="text"
    else:blocks=[dict(block("x"),id="mask-customer")]
    with pytest.raises(ValueError):policy(rs,blocks)

@pytest.mark.parametrize("body",['{"text":"Customer AG"','{"text":"Customer AG","text":"hello"}','{"text":"Customer AG","n":NaN}'])
def test_bad_json_blocks_transform(body):
    with pytest.raises(ValueError):e.replace_text(policy(),body)

def test_expansion_limit():
    r=repl();r.update(find="A",replace_with="x"*2000,boundary="substring")
    p=policy([r]);p["inspection"]["max_input_bytes"]=1024
    with pytest.raises(e.InspectionLimit):e.replace_text(p,"A")

def test_input_limit():
    p=policy();p["inspection"]["max_input_bytes"]=1024
    with pytest.raises(e.InspectionLimit):e.replace_text(p,"x"*1025)

def test_opaque_value_remains_blocked():
    p=policy(rules=[block("Customer AG")]);text,_=e.replace_text(p,'{"id":"Customer AG","text":"hello"}')
    assert e.inspect(p,text)

class Request:
    def __init__(self,text,headers=None):self._text=text;self.raw_content=text.encode();self.headers=headers or {};self.stream=False
    def get_text(self,strict=True):return self._text
    @property
    def text(self):return self._text
    @text.setter
    def text(self,v):self._text=v;self.raw_content=v.encode();self.headers["content-length"]=str(len(self.raw_content))

@pytest.fixture
def addon(monkeypatch,tmp_path):
    context=SimpleNamespace(options=SimpleNamespace(request_log=str(tmp_path/"audit.jsonl"),secret_keeper_ws_client="copilot"))
    calls=[];context.master=SimpleNamespace(commands=SimpleNamespace(call=lambda *a:calls.append(a)))
    response=SimpleNamespace(make=lambda code,body,headers:SimpleNamespace(status_code=code,content=body))
    monkeypatch.setitem(sys.modules,"mitmproxy",SimpleNamespace(ctx=context,http=SimpleNamespace(HTTPFlow=object,Response=response)))
    mod=load("replacement_addon","src/secret_keeper/request_capture.py")
    obj=mod.RequestCapture();obj.policy=policy();obj.policy_error=False
    flow=SimpleNamespace(id="test",response=None,request=Request('{"text":"Customer AG"}',{"content-type":"application/json"}),websocket=SimpleNamespace(messages=[]),kill=lambda:None)
    obj.capture.configure(SimpleNamespace(capture_mode="full",capture_file=str(tmp_path/"capture.jsonl"),request_log=str(tmp_path/"audit.jsonl")))
    return obj,flow,tmp_path,calls

def test_http_modifies_and_captures(addon):
    obj,flow,temp,calls=addon;obj.request(flow)
    assert flow.response is None and json.loads(flow.request.text)["text"]=="[CUSTOMER]"
    records=[json.loads(x) for x in (temp/"capture.jsonl").read_text().splitlines()]
    assert [x["capture_stage"] for x in records]==["attempted_outbound","transformed_outbound"]
    assert "Customer AG" in records[0]["body_text"] and "Customer AG" not in records[1]["body_text"]
    audit=(temp/"audit.jsonl").read_text();assert '"decision": "REPLACE"' in audit
    assert "Customer AG" not in audit and "[CUSTOMER]" not in audit
    assert "transformed_outbound" in (temp/"capture.jsonl.txt").read_text()

def test_http_post_replacement_block(addon):
    obj,flow,temp,_=addon;obj.policy=policy(rules=[block("secret")]);flow.request=Request('Customer AG secret')
    obj.request(flow);assert flow.response.status_code==422
    assert flow.request.text=='Customer AG secret'
    records=[json.loads(x) for x in (temp/"capture.jsonl").read_text().splitlines()]
    assert records[-1]["capture_stage"]=="replacement_candidate" and records[-1]["final_decision"]=="BLOCK"

def test_ws_modified(addon):
    obj,flow,temp,_=addon
    msg=SimpleNamespace(from_client=True,injected=False,content=b'{"type":"response.create","input":[{"role":"user","content":[{"type":"input_text","text":"Customer AG"}]}]}',dropped=False)
    msg.drop=lambda:setattr(msg,"dropped",True);flow.websocket.messages=[msg]
    obj.websocket_message(flow)
    assert b'Customer AG' not in msg.content and b'[CUSTOMER]' in msg.content and not msg.dropped

def test_ws_block_not_bypassed(addon):
    obj,flow,temp,calls=addon;obj.policy=policy(rules=[block("secret")])
    msg=SimpleNamespace(from_client=True,injected=False,content=b'{"type":"response.create","text":"Customer AG secret"}',dropped=False)
    original=msg.content;msg.drop=lambda:setattr(msg,"dropped",True);flow.websocket.messages=[msg]
    obj.websocket_message(flow);assert msg.dropped and msg.content==original and len(calls)==9

@pytest.mark.parametrize("headers",[{"content-type":"multipart/form-data"},{"content-type":"application/json","digest":"signed"}])
def test_unsupported_mutation_block(addon,headers):
    obj,flow,temp,_=addon;flow.request=Request('{"text":"Customer AG"}',headers)
    obj.request(flow);assert flow.response.status_code==422 and b"replacement_error" in flow.response.content

def test_policy_error_never_replaces(addon):
    obj,flow,temp,_=addon;obj.policy_error=True;obj.request(flow)
    assert flow.response.status_code==422 and "Customer AG" in flow.request.text


def test_json_escaped_name():
    body='{"text":"Customer \u0041G"}'
    assert json.loads(e.replace_text(policy(),body)[0])["text"]=="[CUSTOMER]"

def test_plain_regex_metacharacters_literal():
    r=repl();r.update(find="A.*B",boundary="substring")
    assert e.replace_text(policy([r]),"A.*B AxB")[0]=="[CUSTOMER] AxB"

def test_no_normalization_silent_change():
    assert e.replace_text(policy(),"Customer  AG")[0]=="Customer  AG"

def test_exact_equal_overlap_policy_order():
    a=repl();b=dict(a,id="second",replace_with="SECOND")
    assert e.replace_text(policy([a,b]),"Customer AG")[0]=="[CUSTOMER]"

def test_incoming_ws_not_changed(addon):
    obj,flow,temp,_=addon
    msg=SimpleNamespace(from_client=False,injected=False,content=b'{"text":"Customer AG"}')
    flow.websocket.messages=[msg];obj.websocket_message(flow)
    assert msg.content==b'{"text":"Customer AG"}'

def test_message_match_limit():
    p=policy();p["inspection"]["max_views"]=16
    with pytest.raises(e.InspectionLimit):e.replace_text(p,"Customer AG "*17)

def test_failed_http_assignment_blocks(addon):
    obj,flow,temp,_=addon
    class Broken(Request):
        @Request.text.setter
        def text(self,value):raise ValueError("cannot encode")
    flow.request=Broken('Customer AG')
    obj.request(flow);assert flow.response.status_code==422 and b"replacement_error" in flow.response.content
