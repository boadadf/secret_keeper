"""Standalone mitmproxy addon. Policy is loaded at startup; restart after edits."""
import json
import os
import re
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from mitmproxy import ctx, http

CANARY = "SECRET_KEEPER_CONFIDENTIAL_CANARY"
DEFAULT_POLICY = Path(__file__).resolve().parents[2] / "config" / "secret-keeper-policy.json"
FIELDS = {"password", "passwd", "pwd", "apikey", "apisecret", "clientsecret", "accesstoken", "refreshtoken", "secretkey", "privatekey"}
PRIVATE = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")
TOKENS = re.compile(r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36}|AKIA[A-Z0-9]{16})(?![A-Za-z0-9_])")
ASSIGN = re.compile(r"(?i)\b(password|passwd|pwd|api[_-]?key|api[_-]?secret|client[_-]?secret|access[_-]?token|refresh[_-]?token|secret[_-]?key)\b\s*[:=]\s*(?:\"([^\"\r\n]+)\"|'([^'\r\n]+)'|([^\s,;\}\]]+))")


def normalize(value):
    return " ".join(unicodedata.normalize("NFKC", value).casefold().split())


def credential(value):
    value = value.strip()
    # Narrow placeholders only. This is not a general validation of secret authenticity.
    return bool(value) and value.casefold() not in {"<redacted>", "[redacted]", "***", "${password}", "${api_key}"}


def validate_policy(policy):
    if not isinstance(policy, dict) or set(policy) - {"schema_version", "canary_enabled", "secrets_enabled", "dictionary"}:
        raise ValueError("unknown policy field")
    if policy.get("schema_version") != 1:
        raise ValueError("unsupported policy schema")
    for key in ("canary_enabled", "secrets_enabled"):
        if type(policy.get(key)) is not bool:
            raise ValueError("policy booleans required")
    entries = policy.get("dictionary")
    if not isinstance(entries, list):
        raise ValueError("dictionary must be a list")
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"id", "values", "boundary"}:
            raise ValueError("invalid dictionary entry")
        ident = entry["id"]
        if not isinstance(ident, str) or not re.fullmatch(r"[a-z0-9_-]{1,64}", ident) or ident in seen:
            raise ValueError("invalid or duplicate opaque entry ID")
        seen.add(ident)
        if entry["boundary"] not in {"whole_phrase", "substring"}:
            raise ValueError("invalid boundary")
        if not isinstance(entry["values"], list) or not entry["values"]:
            raise ValueError("values required")
        if any(not isinstance(v, str) or len(normalize(v)) < 3 for v in entry["values"]):
            raise ValueError("dictionary values must contain at least three normalized characters")
    return policy


class RequestCapture:
    def __init__(self):
        self.policy = None
        self.policy_error = False

    def load(self, loader):
        loader.add_option("request_log", str, "", "Opt-in metadata-only JSONL audit path")
        loader.add_option("secret_keeper_policy", str, str(DEFAULT_POLICY), "Local JSON policy file")

    def configure(self, updated):
        if self.policy is None or "secret_keeper_policy" in updated:
            try:
                self.policy = validate_policy(json.loads(Path(ctx.options.secret_keeper_policy).read_text(encoding="utf-8")))
                self.policy_error = False
                ctx.log.info("Secret Keeper policy loaded; canary=" + str(self.policy["canary_enabled"]))
            except (OSError, ValueError, TypeError):
                self.policy_error = True
                ctx.log.error("Secret Keeper POLICY ERROR: fix local policy and restart; requests will be blocked")

    def requestheaders(self, flow: http.HTTPFlow):
        flow.request.stream = False

    def responseheaders(self, flow: http.HTTPFlow):
        flow.response.stream = True

    def text_match(self, text, location):
        policy = self.policy
        if policy["canary_enabled"] and CANARY in text:
            return {"rule_id": "test_canary", "location": location}
        norm = normalize(text)
        for entry in policy["dictionary"]:
            for value in entry["values"]:
                phrase = re.escape(normalize(value))
                pattern = phrase if entry["boundary"] == "substring" else r"(?<!\w)" + phrase + r"(?!\w)"
                if re.search(pattern, norm):
                    return {"rule_id": "dictionary", "entry_id": entry["id"], "location": location}
        if policy["secrets_enabled"]:
            if PRIVATE.search(text):
                return {"rule_id": "private_key_block", "location": location}
            if TOKENS.search(text):
                return {"rule_id": "supported_token_format", "location": location}
            for match in ASSIGN.finditer(text):
                if credential(next(v for v in match.groups()[1:] if v is not None)):
                    return {"rule_id": "credential_assignment", "location": location}
        return None

    def inspect(self, text):
        if self.policy_error or self.policy is None:
            return {"rule_id": "policy_error", "location": "policy"}
        try:
            value = json.loads(text)
        except ValueError:
            return self.text_match(text, "body.text")
        stack = [(value, "body", None)]
        while stack:
            item, location, field = stack.pop()
            if isinstance(item, str):
                if self.policy["secrets_enabled"] and field in FIELDS and credential(item):
                    return {"rule_id": "credential_field", "location": location}
                result = self.text_match(item, location)
                if result:
                    return result
            elif isinstance(item, dict):
                for index, (key, val) in enumerate(item.items()):
                    # Numeric positions avoid logging customer-supplied JSON keys.
                    loc = location + ".object[" + str(index) + "]"
                    result = self.text_match(key, loc + ".key")
                    if result:
                        return result
                    field_name = re.sub(r"[^a-z]", "", key.casefold())
                    stack.append((val, loc + ".value", field_name))
            elif isinstance(item, list):
                stack.extend((val, location + ".array[" + str(i) + "]", field) for i, val in enumerate(item))
        # Also check serialized text for structured sequences crossing JSON values.
        return self.text_match(text, "body.serialized")

    def audit(self, flow, transport, decision, details=None):
        record = {"schema_version": 4, "timestamp": datetime.now(timezone.utc).isoformat(),
                  "flow_id": flow.id, "transport": transport, "direction": "client_to_server",
                  "decision": decision}
        record.update(details or {})
        if decision == "BLOCK":
            ctx.log.error("Secret Keeper BLOCK " + json.dumps(record, ensure_ascii=True))
        path = ctx.options.request_log
        if not path:
            return
        try:
            target = Path(path).expanduser()
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as out:
                out.write(json.dumps(record, ensure_ascii=True) + "\n")
        except OSError:
            ctx.log.error("Secret Keeper audit write failed")

    def request(self, flow: http.HTTPFlow):
        try:
            raw = flow.request.raw_content
            if raw is None:
                result = {"rule_id": "body_unavailable", "location": "body"}
            else:
                text = flow.request.get_text(strict=True)
                result = self.inspect(text or "")
        except (ValueError, RecursionError):
            result = {"rule_id": "inspection_error", "location": "body"}
        if result:
            flow.response = http.Response.make(422,
                json.dumps({"error": {"code": "secret_keeper_blocked", "message": "Local content policy rejected this request.",
                                      "rule_id": result["rule_id"]}}).encode(),
                {"Content-Type": "application/json", "Cache-Control": "no-store"})
            self.audit(flow, "http", "BLOCK", result)
        else:
            self.audit(flow, "http", "ALLOW")

    def websocket_message(self, flow: http.HTTPFlow):
        if not flow.websocket or not flow.websocket.messages:
            return
        message = flow.websocket.messages[-1]
        if not message.from_client:
            return
        try:
            result = self.inspect(message.content.decode("utf-8", errors="strict"))
        except (ValueError, RecursionError):
            result = {"rule_id": "inspection_error", "location": "body"}
        if result:
            message.drop()
            self.audit(flow, "websocket", "BLOCK", result)
        else:
            self.audit(flow, "websocket", "ALLOW")


addons = [RequestCapture()]
