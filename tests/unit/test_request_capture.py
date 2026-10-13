import base64
import copy
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from urllib.parse import quote
import pytest

ROOT=Path(__file__).resolve().parents[2]
_spec=importlib.util.spec_from_file_location("tested_rules",ROOT/"src/secret_keeper/rules.py")
e=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(e)


def r(kind,**options):return dict(id="test-rule",type=kind,enabled=True,action="block",**options)
def policy(rule,decode=False):
    p={"schema_version":2,"rules":[rule]}
    if decode:p["inspection"]={"decode_depth":2,"decoders":["percent","hex","base64"]}
    return e.validate_policy(p)
def match(rule,text,decode=False):return e.inspect(policy(rule,decode),text)

@pytest.mark.parametrize("text,expected",[
("https://reports.example.internal/customer",True),
("https://EXAMPLE.INTERNAL./",True),
("https://example.internal.attacker.test/",False),
("https://example.internal@attacker.test/",False),
("https://public.example/",False)])
def test_domains(text,expected):
    assert bool(match(r("url_domain",domains=["example.internal"],include_subdomains=True),text))==expected

@pytest.mark.parametrize("text,expected",[("alice@customer.example",True),("alice@sub.customer.example",True),("restricted@example.test",True),("alice@customer.example.attacker.test",False),("alice@public.example",False)])
def test_email(text,expected):
    assert bool(match(r("email",domains=["customer.example"],include_subdomains=True,addresses=["restricted@example.test"]),text))==expected

@pytest.mark.parametrize("text,expected",[("10.20.1.2",True),("10.21.1.2",False),("999.20.1.2",False),("fd12:3456:789a::1",True),("https://[fd12:3456:789a::1]/",True),("2001:db8::1",False)])
def test_network(text,expected):
    assert bool(match(r("ip_network",networks=["10.20.0.0/16","fd12:3456:789a::/48"]),text))==expected

@pytest.mark.parametrize("text,expected",[('{"username":"synthetic-user-001"}',True),('{"login":"SYNTHETIC-USER-001"}',True),('{"username":"other"}',False),("synthetic-user-001",False)])
def test_field(text,expected):
    assert bool(match(r("field",fields=["username","login"],values=["synthetic-user-001"],case_sensitive=False),text))==expected


def test_field_any_and_numeric():
    rule=r("field",fields=["employee_id"],values=[],case_sensitive=False)
    assert match(rule,'{"employee_id":12345}')
    assert not match(rule,'{"employee_id":""}')

@pytest.mark.parametrize("text,expected",[("postgresql://u:synthetic@db.example/app",True),("Server=db;Password=synthetic;",True),("https://public.example/?token=synthetic",True),("https://public.example/?X-Amz-Signature=synthetic",True),("postgresql://db.example/app",False),("https://public.example/?page=1",False)])
def test_connection(text,expected):
    assert bool(match(r("builtin",detector="connection_string"),text))==expected

@pytest.mark.parametrize("token",["ghp_"+"A"*36,"github_pat_"+"A"*82,"glpat-"+"A"*20,"sk_live_"+"A"*24,"xoxb-"+"A"*24,"AKIA"+"A"*16])
def test_tokens(token):assert match(r("builtin",detector="supported_token_format"),token)

@pytest.mark.parametrize("detector,text,expected",[
("credit_card","4111 1111 1111 1111",True),("credit_card","4111 1111 1111 1112",False),
("iban","GB82 WEST 1234 5698 7654 32",True),("iban","GB83 WEST 1234 5698 7654 32",False),
("phone_candidate","+44 20 7946 0958",True),("phone_candidate","Discuss phone numbers",False),
("hash_candidate","a"*64,True),("hash_candidate","hello",False),
("entropy_candidate","Ab3Cd4Ef5Gh6Ij7Kl8Mn9Op0Qr1St2Uv3Wx4Yz5",True),
("entropy_candidate","a"*64,False)])
def test_candidates(detector,text,expected):assert bool(match(r("builtin",detector=detector),text))==expected

@pytest.mark.parametrize("encoding",["percent","hex","base64","double-base64","encoded-json"])
def test_decoders(encoding):
    text=e.CANARY
    if encoding=="percent":encoded="".join("%"+format(b,"02X") for b in text.encode())
    elif encoding=="hex":encoded=text.encode().hex()
    elif encoding=="base64":encoded=base64.b64encode(text.encode()).decode()
    elif encoding=="double-base64":encoded=base64.b64encode(base64.b64encode(text.encode())).decode()
    else:encoded=base64.b64encode(json.dumps({"message":text}).encode()).decode()
    rule=r("exact_text",value=text)
    assert not match(rule,encoded)
    found=match(rule,encoded,True)
    assert found and "decoded_" in found[0]["location"]


def test_decode_preserves_fields():
    value=base64.b64encode(b"synthetic-user-001").decode()
    assert match(r("field",fields=["username"],values=["synthetic-user-001"],case_sensitive=False),json.dumps({"username":value}),True)


def test_json_escape():
    assert match(r("exact_text",value=e.CANARY),json.dumps({"x":e.CANARY}).replace("SECRET",r"\u0053ECRET"))


def test_resource():
    assert match(r("resource",values=["/srv/secretkeeper-test/private/"],case_sensitive=True),"/srv/secretkeeper-test/private/doc.txt")


def test_limits():
    p=policy(r("exact_text",value="sensitive"));p["inspection"]["max_input_bytes"]=1024
    with pytest.raises(e.InspectionLimit):e.inspect(p,"x"*1025)
    p["inspection"]["max_views"]=16
    with pytest.raises(e.InspectionLimit):e.inspect(p,json.dumps(list(range(30))))


def test_legacy():
    p=e.validate_policy({"schema_version":1,"canary_enabled":True,"secrets_enabled":True,"dictionary":[{"id":"customer-001","values":["Northstar Manufacturing"],"boundary":"whole_phrase"}]})
    for text,id in [(e.CANARY,"test_canary"),("Northstar Manufacturing","dictionary"),('password="synthetic"',"credential_assignment")]:
        assert any(m["rule_id"]==id for m in e.inspect(p,text))


def test_old_schema2():
    p=e.validate_policy({"schema_version":2,"rules":[r("exact_text",value=e.CANARY)]})
    assert p["inspection"]["decode_depth"]==0 and e.inspect(p,e.CANARY)

@pytest.mark.parametrize("mutation",["duplicate","domain","network","unknown","bad-limit","bad-decoder","bool"])
def test_invalid(mutation):
    p={"schema_version":2,"rules":[r("exact_text",value="test")]}
    if mutation=="duplicate":p["rules"].append(copy.deepcopy(p["rules"][0]))
    elif mutation=="domain":p["rules"]=[r("url_domain",domains=["https://example.internal"],include_subdomains=True)]
    elif mutation=="network":p["rules"]=[r("ip_network",networks=["10.20.1.1/16"])]
    elif mutation=="unknown":p["rules"][0]["ignore"]=True
    elif mutation=="bad-limit":p["inspection"]={"decode_depth":999}
    elif mutation=="bad-decoder":p["inspection"]={"decoders":["gzip"]}
    else:p["rules"][0]["enabled"]="true"
    with pytest.raises(ValueError):e.validate_policy(p)

@pytest.fixture
def addon(monkeypatch,tmp_path):
    context=SimpleNamespace(options=SimpleNamespace(request_log=str(tmp_path/"audit.jsonl")))
    response=SimpleNamespace(make=lambda code,body,headers:SimpleNamespace(status_code=code,content=body))
    monkeypatch.setitem(sys.modules,"mitmproxy",SimpleNamespace(ctx=context,http=SimpleNamespace(HTTPFlow=object,Response=response)))
    spec=importlib.util.spec_from_file_location("proxy_under_test",ROOT/"src/secret_keeper/request_capture.py")
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    obj=mod.RequestCapture();obj.policy=mod.validate_policy({"schema_version":2,"rules":[r("exact_text",value="SYNTHETIC")]});obj.policy_error=False
    flow=SimpleNamespace(id="test",kill=lambda:None,response=None,request=SimpleNamespace(raw_content=b"hello",get_text=lambda strict:"hello",stream=True),websocket=SimpleNamespace(messages=[]))
    return obj,flow,context,tmp_path,mod

@pytest.mark.parametrize("mode",["block","audit","disabled","conflict"])
def test_modes(addon,mode):
    obj,flow,context,temp,mod=addon
    rules=[dict(r("exact_text",value="SYNTHETIC"),action="audit" if mode in ("audit","conflict") else "block",enabled=mode!="disabled")]
    if mode=="conflict":rules.append(dict(r("exact_text",value="SYNTHETIC"),id="other-block"))
    obj.policy=mod.validate_policy({"schema_version":2,"rules":rules})
    flow.request.get_text=lambda strict:"SYNTHETIC";obj.request(flow)
    assert (flow.response is not None)==(mode in ("block","conflict"))
    message=SimpleNamespace(from_client=True,content=b"SYNTHETIC",dropped=False)
    message.drop=lambda:setattr(message,"dropped",True)
    flow.websocket.messages.append(message);obj.websocket_message(flow)
    assert message.dropped==(mode in ("block","conflict"))
    records=[json.loads(l) for l in (temp/"audit.jsonl").read_text().splitlines()]
    if mode=="audit":assert any(r["decision"]=="AUDIT" and r["final_decision"]=="ALLOW" for r in records)
    if mode=="conflict":assert any(r["decision"]=="AUDIT" and r["final_decision"]=="BLOCK" for r in records)
    assert "SYNTHETIC" not in (temp/"audit.jsonl").read_text()


def test_inspection_limit_block(addon):
    obj,flow,_,_,_=addon;obj.policy["inspection"]["max_input_bytes"]=1024
    flow.request.get_text=lambda strict:"x"*1025;obj.request(flow)
    assert flow.response.status_code==422 and b"inspection_limit" in flow.response.content


def test_policy_error(addon):
    obj,flow,*_=addon;obj.policy_error=True;obj.request(flow)
    assert flow.response.status_code==422


def test_no_logging(addon):
    obj,flow,context,temp,_=addon;context.options.request_log=""
    flow.request.get_text=lambda strict:"SYNTHETIC";obj.request(flow)
    assert flow.response.status_code==422 and not (temp/"audit.jsonl").exists()


def test_normal(addon):
    obj,flow,*_=addon;obj.request(flow);assert flow.response is None


def test_example_defaults():
    p=e.validate_policy(json.loads((ROOT/"config/secret-keeper-policy.example.json").read_text()))
    assert not any(m["action"]=="block" for m in e.inspect(p,"Reply with hello."))
    for name in ("hash_candidate","entropy_candidate","phone_candidate","credit_card","iban"):
        assert next(r for r in p["rules"] if r.get("detector")==name)["action"]=="audit"
