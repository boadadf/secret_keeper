import importlib.util
import json
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location("deterministic_v11",ROOT/"src/secret_keeper/rules.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def rule(kind,**kw):return dict(id="test-rule",type=kind,enabled=True,action="block",**kw)
def inspect(r,text):return m.inspect(m.validate_policy({"schema_version":2,"rules":[r]}),text)

LABELS=["password","passwd","pwd","API key","api_key","API secret","client secret","access token","refresh token","secret key","private key"]
FORMS=["My {label} is synthetic-test-value","The {label} equals synthetic-test-value","Use this {label} to login: synthetic-test-value","Use this {label} for authentication: synthetic-test-value","{label}: \"synthetic-test-value\"","Use synthetic-test-value as the {label}","{label} = synthetic-test-value","{label}:\nsynthetic-test-value"]

@pytest.mark.parametrize("label",LABELS)
@pytest.mark.parametrize("form",FORMS)
@pytest.mark.parametrize("wrapped",[False,True])
def test_explicit_credentials(label,form,wrapped):
    text=form.format(label=label)
    if wrapped:text=json.dumps({"messages":[{"role":"user","content":text}]})
    assert inspect(rule("builtin",detector="credential_assignment"),text)

@pytest.mark.parametrize("text",["Explain how passwords work","How do I reset my password?","Never share your password","A password is a secret","The password is hashed","The password is encrypted","The password is strong","My password is forgotten","The API key is confidential","Use a password manager","The access token is not available","password: [redacted]","password=***","password: ${password}"])
def test_harmless_credential_discussion(text):
    assert not inspect(rule("builtin",detector="credential_assignment"),text)

CASES=[
(rule("exact_text",value="PROTECTED_MARKER"),"Use PROTECTED_MARKER here","Explain marker detection"),
(rule("dictionary",matching=dict(m.MATCHING),entries=[{"id":"customer-001","values":["Northstar Manufacturing"]}]),"Our customer is NORTHSTAR   Manufacturing.","Our customer is Northstar Manufacturingx"),
(rule("builtin",detector="credential_assignment"),"Use this password to login: my-secret","Explain how passwords work"),
(rule("builtin",detector="credential_field"),'{"api_key":"synthetic-value"}','{"api_key":"[redacted]"}'),
(rule("builtin",detector="private_key_block"),"Key:\n-----BEGIN PRIVATE KEY-----\nSYNTHETIC\n-----END PRIVATE KEY-----","Explain private key formats"),
(rule("builtin",detector="supported_token_format"),"My key is ghp_"+"A"*36,"Explain API tokens"),
(rule("builtin",detector="connection_string"),"Connect to postgresql://user:synthetic@db.example/app","Connect to postgresql://db.example/app"),
(rule("builtin",detector="connection_string"),"https://example.test/?refresh_token=synthetic","https://example.test/?page=1"),
(rule("builtin",detector="credit_card"),"Pay with 4111 1111 1111 1111 please","Pay with 4111 1111 1111 1112 please"),
(rule("builtin",detector="iban"),"Transfer to GB82 WEST 1234 5698 7654 32 please","Transfer to GB83 WEST 1234 5698 7654 32 please"),
(rule("builtin",detector="phone_candidate"),"Call me at +44 (20) 7946 0958.","Explain phone numbers"),
(rule("builtin",detector="hash_candidate"),"Hash: "+"a"*64,"Explain SHA-256 hashes"),
(rule("builtin",detector="entropy_candidate"),"Value: Ab3Cd4Ef5Gh6Ij7Kl8Mn9Op0Qr1St2Uv3Wx4Yz5","Value: "+"a"*64),
(rule("url_domain",domains=["customer.example"],include_subdomains=True),"Visit https://sub.customer.example/report","Visit https://customer.example.attacker.test/report"),
(rule("email",domains=["customer.example"],include_subdomains=True,addresses=[]),"Email alice@customer.example please","Email alice@public.example please"),
(rule("ip_network",networks=["10.20.0.0/16","fd12:3456:789a::/48"]),"Server: 10.20.1.2","Server: 10.21.1.2"),
(rule("ip_network",networks=["fd12:3456:789a::/48"]),"Server: https://[fd12:3456:789a::1]/","Server: https://[2001:db8::1]/"),
(rule("field",fields=["username"],values=["synthetic-user"],case_sensitive=False),"My username is SYNTHETIC-USER","My username is another-user"),
(rule("resource",values=["internal-repo"],case_sensitive=False),"Use INTERNAL-REPO please","Use public-repo please")]

@pytest.mark.parametrize("r,positive,negative",CASES)
@pytest.mark.parametrize("action",["block","audit","disabled"])
@pytest.mark.parametrize("wrapper",["plain","json","nested"])
def test_all_categories(r,positive,negative,action,wrapper):
    r=dict(r,action="audit" if action=="audit" else "block",enabled=action!="disabled")
    def wrap(t):
        if wrapper=="json":return json.dumps({"messages":[{"content":t}]})
        if wrapper=="nested":return json.dumps({"data":json.dumps({"content":t})})
        return t
    found=inspect(r,wrap(positive))
    assert bool(found)==(action!="disabled")
    if found:assert found[0]["action"]==action
    assert not inspect(r,wrap(negative))

@pytest.mark.parametrize("text",["GB82WEST12345698765432","gb82 west 1234 5698 7654 32","GB82\u00a0WEST\u00a01234\u00a05698\u00a07654\u00a032","GB82\tWEST\t1234\t5698\t7654\t32","GB82\nWEST\n1234\n5698\n7654\n32","GB82 WEST 1234 5698 7654 32 is my IBAN"])
def test_iban_formatting(text):assert inspect(rule("builtin",detector="iban"),text)

@pytest.mark.parametrize("text",["4111-1111-1111-1111","4111\u00a01111\u00a01111\u00a01111","4111\t1111\t1111\t1111"])
def test_card_formatting(text):assert inspect(rule("builtin",detector="credit_card"),text)

@pytest.mark.parametrize("text",["My employee id is 12345","employee_id: 12345",'{"employee_id":12345}'])
def test_configured_fields(text):assert inspect(rule("field",fields=["employee_id"],values=["12345"],case_sensitive=True),text)

@pytest.mark.parametrize("text",["My password is [redacted]","password: ${password}","password: <redacted>"])
@pytest.mark.parametrize("wrapper",["plain","json","nested"])
def test_placeholders_across_wrappers(text,wrapper):
    if wrapper=="json":text=json.dumps({"content":text})
    elif wrapper=="nested":text=json.dumps({"data":json.dumps({"content":text})})
    assert not inspect(rule("builtin",detector="credential_assignment"),text)

def test_embedded_json_depth_limit():
    text='{"password":"synthetic"}'
    for _ in range(5):text=json.dumps({"data":text})
    policy=m.validate_policy({"schema_version":2,"rules":[],"inspection":{"max_json_depth":4}})
    with pytest.raises(m.InspectionLimit):m.inspect(policy,text)
