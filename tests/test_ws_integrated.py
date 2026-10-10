import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1] / "src" / "secret_keeper"

class Tests(unittest.TestCase):
    def setUp(self):
        self.calls=[]
        self.ctx=SimpleNamespace(options=SimpleNamespace(request_log="", secret_keeper_ws_client="copilot"), master=SimpleNamespace(commands=SimpleNamespace(call=lambda *a:self.calls.append(a))))
        sys.modules["mitmproxy"]=SimpleNamespace(ctx=self.ctx, http=SimpleNamespace(HTTPFlow=object, Response=SimpleNamespace(make=lambda *a:a)))
        spec=importlib.util.spec_from_file_location("integrated_capture", ROOT/"request_capture.py")
        self.mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.mod)
        self.obj=self.mod.RequestCapture()
        self.obj.policy=self.mod.validate_policy({"schema_version":2,"rules":[{"id":"existing-block","type":"exact_text","action":"block","enabled":True,"value":"TEST_BLOCK"}]})
        self.obj.policy_error=False
        self.flow=SimpleNamespace(id="flow", websocket=SimpleNamespace(messages=[]), killed=False)
        self.flow.kill=lambda:setattr(self.flow,"killed",True)
    def send(self, payload, client=True, injected=False):
        msg=SimpleNamespace(from_client=client,content=json.dumps(payload).encode(),injected=injected,dropped=False)
        msg.drop=lambda:setattr(msg,"dropped",True)
        self.flow.websocket.messages.append(msg);self.obj.websocket_message(self.flow)
        return msg
    def test_existing_rule_injects(self):
        msg=self.send({"type":"response.create","input":"TEST_BLOCK"})
        self.assertTrue(msg.dropped);self.assertEqual(len(self.calls),9)
        self.assertTrue(all(c[0]=="inject.websocket" and c[2] is True for c in self.calls))
        events=[json.loads(c[3]) for c in self.calls]
        self.assertEqual([e["sequence_number"] for e in events],list(range(9)))
        self.assertEqual(events[-1]["response"]["status"],"completed")
        self.assertIsNone(events[-1]["response"]["usage"])
        self.assertIn("existing-block",events[4]["delta"])
        self.assertFalse(self.flow.killed)
    def test_allow(self):
        self.assertFalse(self.send({"type":"response.create","input":"hello"}).dropped)
        self.assertFalse(self.calls)
    def test_audit_only(self):
        self.obj.policy["rules"][0]["action"]="audit"
        self.assertFalse(self.send({"type":"response.create","input":"TEST_BLOCK"}).dropped)
        self.assertFalse(self.calls)
    def test_legacy_none(self):
        self.ctx.options.secret_keeper_ws_client="none"
        self.assertTrue(self.send({"type":"response.create","input":"TEST_BLOCK"}).dropped)
        self.assertFalse(self.calls);self.assertFalse(self.flow.killed)
    def test_unknown_protocol(self):
        self.assertTrue(self.send({"type":"unknown","input":"TEST_BLOCK"}).dropped)
        self.assertTrue(self.flow.killed);self.assertFalse(self.calls)
    def test_concurrent(self):
        self.send({"type":"response.create","input":"hello"})
        self.send({"type":"response.create","input":"TEST_BLOCK"})
        self.assertTrue(self.flow.killed);self.assertFalse(self.calls)
    def test_terminal_clears(self):
        self.send({"type":"response.create","input":"hello"})
        self.send({"type":"response.completed"},client=False)
        self.send({"type":"response.create","input":"TEST_BLOCK"})
        self.assertEqual(len(self.calls),9)
    def test_injected_skip(self):
        self.send({"type":"response.create","input":"TEST_BLOCK"},injected=True)
        self.assertFalse(self.calls)
    def test_continuation(self):
        self.send({"type":"response.create","input":"TEST_BLOCK"})
        rid=json.loads(self.calls[-1][3])["response"]["id"]
        self.assertTrue(self.send({"type":"response.create","input":"hello","previous_response_id":rid}).dropped)
        self.assertEqual(len(self.calls),18)
    def test_cleanup(self):
        self.send({"type":"response.create","input":"TEST_BLOCK"})
        self.obj.websocket_end(self.flow)
        self.assertNotIn(self.flow.id,self.obj.ws_local_ids)
    def test_policy_error(self):
        self.obj.policy_error=True
        self.assertTrue(self.send({"type":"response.create","input":"hello"}).dropped)
        self.assertEqual(len(self.calls),9)

if __name__=="__main__":unittest.main()
