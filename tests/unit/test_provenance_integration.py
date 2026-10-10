import json
from types import SimpleNamespace
from test_request_capture import addon

def setup(obj,f,mod):
    f.request.headers={"authorization":"Bearer synthetic"};f.request.host="api.example.test"
    obj.policy=mod.validate_policy({"schema_version":2,"rules":[{"id":"credential","type":"builtin","detector":"credential_assignment","enabled":True,"action":"block"}]})
    obj.provenance.remember(mod._provenance.scope(f),(mod._provenance.digest("Explain"),),'Password: "synthetic-value"')
    body={"messages":[{"role":"user","content":"Explain"},{"role":"assistant","content":'Password: "synthetic-value"'},{"role":"user","content":"Continue"}]}
    return body

def test_verified_history_does_not_block(addon):
    obj,f,ctx,tmp,mod=addon;body=setup(obj,f,mod)
    assert obj.evaluate(json.dumps(body),f)==[]

def test_new_user_secret_still_blocks(addon):
    obj,f,ctx,tmp,mod=addon;body=setup(obj,f,mod);body["messages"][-1]["content"]='password="new-synthetic-secret"'
    assert obj.evaluate(json.dumps(body),f)[0]["detector"]=="credential_assignment"

def test_other_rules_still_block(addon):
    obj,f,ctx,tmp,mod=addon;body=setup(obj,f,mod)
    obj.policy["rules"].append({"id":"protected","type":"exact_text","enabled":True,"action":"block","value":"synthetic-value"})
    matches=obj.evaluate(json.dumps(body),f)
    assert len(matches)==1 and matches[0]["rule_id"]=="protected"

def test_feature_disabled_still_blocks(addon):
    obj,f,ctx,tmp,mod=addon;body=setup(obj,f,mod);ctx.options.sk_allow_verified_assistant_credentials=False
    assert obj.evaluate(json.dumps(body),f)

def test_tool_quoted_answer_still_blocks(addon):
    obj,f,ctx,tmp,mod=addon;body=setup(obj,f,mod);body["messages"][1]["role"]="tool"
    assert obj.evaluate(json.dumps(body),f)

def test_failed_policy_never_exempted(addon):
    obj,f,ctx,tmp,mod=addon;body=setup(obj,f,mod);obj.policy_error=True
    assert obj.evaluate(json.dumps(body),f)[0]["rule_id"]=="policy_error"

def test_content_is_not_changed_on_wire(addon):
    obj,f,ctx,tmp,mod=addon;body=setup(obj,f,mod);before=json.dumps(body)
    obj.evaluate(before,f);assert json.dumps(body)==before
