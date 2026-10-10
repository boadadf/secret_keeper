import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
ROOT=Path(__file__).resolve().parents[1]/"src"/"secret_keeper"
class Tests(unittest.TestCase):
    def setUp(self):
        self.calls=[]
        self.ctx=SimpleNamespace(options=SimpleNamespace(request_log="",secret_keeper_ws_client="copilot"),master=SimpleNamespace(commands=SimpleNamespace(call=lambda *a:self.calls.append(a))))
        response=SimpleNamespace(make=lambda status,body,headers:SimpleNamespace(status_code=status,content=body,headers=headers))
        sys.modules["mitmproxy"]=SimpleNamespace(ctx=self.ctx,http=SimpleNamespace(HTTPFlow=object,Response=response))
        spec=importlib.util.spec_from_file_location("strict_capture",ROOT/"request_capture.py")
        self.mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.mod)
        self.obj=self.mod.RequestCapture();self.obj.policy_error=False
        self.obj.policy=self.mod.validate_policy({"schema_version":2,"rules":[{"id":"existing-rule","type":"exact_text","value":"PROTECTED_TEST","action":"block","enabled":True}]})
        self.flow=SimpleNamespace(id="flow",response=None,websocket=SimpleNamespace(messages=[]),killed=False)
        self.flow.kill=lambda:setattr(self.flow,"killed",True)
    def http(self,text):
        self.flow.response=None
        self.flow.request=SimpleNamespace(raw_content=text.encode(),get_text=lambda strict:text)
        self.obj.request(self.flow)
        return self.flow.response
    def ws(self,payload,client=True,injected=False):
        msg=SimpleNamespace(content=json.dumps(payload).encode(),from_client=client,injected=injected,dropped=False)
        msg.drop=lambda:setattr(msg,"dropped",True)
        self.flow.websocket.messages.append(msg);self.obj.websocket_message(self.flow);return msg
    def test_http_block_actionable(self):
        response=self.http('PROTECTED_TEST')
        self.assertEqual(response.status_code,422)
        error=json.loads(response.content)["error"]
        self.assertIn("Retry with less context",error["message"])
        self.assertNotIn("PROTECTED_TEST",error["message"])
        self.assertEqual(error["reference"],"flow")
    def test_history_still_blocked(self):
        self.assertEqual(self.http('{"history":"PROTECTED_TEST","current":"hello"}').status_code,422)
    def test_clean_next_request_allowed(self):
        self.http('PROTECTED_TEST');self.assertIsNone(self.http('hello'))
    def test_audit_only(self):
        self.obj.policy["rules"][0]["action"]="audit";self.assertIsNone(self.http('PROTECTED_TEST'))
    def test_ws_completion(self):
        msg=self.ws({"type":"response.create","input":"PROTECTED_TEST"})
        self.assertTrue(msg.dropped);self.assertEqual(len(self.calls),9)
        event=json.loads(self.calls[-1][3]);self.assertEqual(event["type"],"response.completed")
        self.assertIsNone(event["response"]["usage"])
        self.assertTrue(all(c[2] is True for c in self.calls))
    def test_unknown_ws(self):
        self.ws({"input":"PROTECTED_TEST"});self.assertTrue(self.flow.killed);self.assertFalse(self.calls)
    def test_no_ws_history_exception(self):
        self.assertTrue(self.ws({"type":"response.create","history":"PROTECTED_TEST","input":"hello"}).dropped)
    def test_policy_error(self):
        self.obj.policy_error=True;self.assertEqual(self.http('hello').status_code,422)
    def test_skip_injection(self):
        self.ws({"type":"response.create","input":"PROTECTED_TEST"},injected=True);self.assertFalse(self.calls)
    def test_capture_notice_is_warning(self):
        text=(ROOT/"payload_capture.py").read_text()
        self.assertIn('LOG.warning("Secret Keeper FULL CAPTURE ACTIVE:',text)
        self.assertNotIn('LOG.error("Secret Keeper FULL CAPTURE ACTIVE:',text)
if __name__=="__main__":unittest.main()
