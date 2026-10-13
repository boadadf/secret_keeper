"""Local deterministic policy engine. No networking or credential validation."""
import base64
import binascii
from collections import Counter
import ipaddress
import json
import math
import re
import unicodedata
from urllib.parse import urlsplit, unquote_to_bytes, parse_qsl

CANARY = "SECRET_KEEPER_CONFIDENTIAL_CANARY"
FIELDS = {"password","passwd","pwd","apikey","apisecret","clientsecret","accesstoken","refreshtoken","secretkey","privatekey"}
BUILTINS = {"credential_assignment","credential_field","private_key_block","supported_token_format","connection_string","credit_card","iban","phone_candidate","hash_candidate","entropy_candidate"}
MATCHING = {"case_sensitive":False,"unicode_normalization":"NFKC","whitespace":"collapse","boundary":"whole_phrase"}
LIMITS = {"max_input_bytes":2097152,"max_views":4096,"max_json_depth":64,"decode_depth":0,"max_decoded_bytes":524288,"decoders":[]}
URL = re.compile(r"(?i)\b[a-z][a-z0-9+.-]{1,31}://[^\s<>\"']{1,8192}")
EMAIL = re.compile(r"(?i)(?<![\w.+-])[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b")
IP_CANDIDATE = re.compile(r"(?<![\w])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{2,64}(?:%[A-Za-z0-9_.-]{1,32})?)(?![\w])")
PRIVATE = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")
TOKENS = re.compile(r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}|AKIA[A-Z0-9]{16}|glpat-[A-Za-z0-9_-]{20}|sk_live_[A-Za-z0-9]{24,128}|xox[baprs]-[A-Za-z0-9-]{20,200})(?![A-Za-z0-9_])")
ASSIGN = re.compile(r"(?i)\b(password|passwd|pwd|api[_-]?key|api[_-]?secret|client[_-]?secret|access[_-]?token|refresh[_-]?token|secret[_-]?key)\b\s*[:=]\s*(?:\"([^\"\r\n]{1,8192})\"|'([^'\r\n]{1,8192})'|([^\s,;\}\]]{1,8192}))")
HASH = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{128}|[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})(?![0-9a-fA-F])")
RANDOM = re.compile(r"(?<![A-Za-z0-9_+/=-])[A-Za-z0-9_+/=-]{32,256}(?![A-Za-z0-9_+/=-])")
CARD = re.compile(r"(?<![A-Za-z0-9])(?:[0-9][ \t\u00a0\u202f-]?){12,18}[0-9](?![A-Za-z0-9])")
IBAN = re.compile(r"(?i)(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}(?![A-Za-z0-9])")
PHONE = re.compile(r"(?<!\w)\+[1-9]\d{0,2}(?:[ .()\u00a0\u202f-]{0,3}[0-9]){7,14}(?!\d)")
ODBC = re.compile(r"(?i)\b(?:password|pwd)\s*=\s*([^;\r\n]{1,8192})")
URI_SECRET_FIELDS = {"password","passwd","pwd","token","apikey","api_key","api-key","secret","api_secret","client_secret","client-secret","access_token","access-token","refresh_token","refresh-token","secret_key","sig","signature","x-amz-signature","x-goog-signature"}


# Explicit English constructions, not general semantic classification.
CREDENTIAL_LABEL = r"(?:password|passwd|pwd|api[ _-]?key|api[ _-]?secret|client[ _-]?secret|access[ _-]?token|refresh[ _-]?token|secret[ _-]?key|private[ _-]?key)"
CREDENTIAL_VALUE = r"(?:((?:\[redacted\]|<redacted>|\$\{[A-Za-z0-9_]+\}))(?![A-Za-z0-9_])|\"([^\"\r\n]{1,8192})\"|'([^'\r\n]{1,8192})'|([^\s,;\}\]\"']{1,8192}))"
NATURAL_FORWARD = re.compile(
    r"(?i)\b" + CREDENTIAL_LABEL +
    r"(?:[ \t]+(?:to[ \t]+(?:log[ \t]?in|sign[ \t]?in|authenticate)|for[ \t]+(?:login|authentication|the[ \t]+account)))?"
    r"(?:[ \t]*(?:[:=])[ \t\r\n]*|[ \t]+(?:is|equals)[ \t]+)" + CREDENTIAL_VALUE)
NATURAL_REVERSE = re.compile(
    r"(?i)\buse[ \t]+" + CREDENTIAL_VALUE +
    r"[ \t]+as[ \t]+(?:my|the|your|our|this)[ \t]+" + CREDENTIAL_LABEL + r"\b")
ASSIGN_V2 = re.compile(r"(?i)\b(" + CREDENTIAL_LABEL + r")\b[\"']?\s*[:=]\s*" + CREDENTIAL_VALUE)
NATURAL_NONVALUES = {"a", "an", "the", "not", "never", "used", "required", "stored", "hashed", "encrypted", "secret", "private", "confidential", "unknown", "missing", "empty", "optional", "secure", "strong", "weak", "important", "sensitive", "correct", "incorrect", "changed", "forgotten", "needed", "protected", "sharing", "true", "false", "null", "none"}

def explicit_credential(value):
    for match in ASSIGN_V2.finditer(value):
        if credential(next(v for v in match.groups()[1:] if v is not None)):
            return True
    for pattern in (NATURAL_FORWARD,NATURAL_REVERSE):
        for match in pattern.finditer(value):
            candidate=next(v for v in match.groups() if v is not None)
            if credential(candidate) and candidate.casefold().rstrip(".!?") not in NATURAL_NONVALUES:
                return True
    return False

def iban_in_text(value):
    # Try bounded candidates at whitespace/punctuation boundaries. The former
    # greedy expression could swallow words after a spaced IBAN.
    for start in re.finditer(r"(?i)(?<![A-Za-z0-9])[A-Z]{2}[0-9]{2}",value):
        pos=start.start();compact=""
        while pos<len(value) and pos-start.start()<128:
            char=value[pos]
            if char.isascii() and char.isalnum():
                compact+=char.upper()
                if len(compact)>34:break
                end=pos+1
                boundary=end==len(value) or not (value[end].isascii() and value[end].isalnum())
                if len(compact)>=15 and boundary and iban(compact):return True
            elif char in " \t\r\n\u00a0\u202f":
                pass
            else:break
            pos+=1
    return False

class InspectionLimit(ValueError):
    pass


def ident(value):
    return isinstance(value,str) and re.fullmatch(r"[a-z0-9_-]{1,64}",value) is not None


def normalize(value, match):
    if match["unicode_normalization"]=="NFKC":value=unicodedata.normalize("NFKC",value)
    if not match["case_sensitive"]:value=value.casefold()
    if match["whitespace"]=="collapse":value=" ".join(value.split())
    return value


def credential(value):
    return bool(value.strip()) and value.strip().casefold() not in {"<redacted>","[redacted]","***","${password}","${api_key}"}


def host(value):
    if not isinstance(value,str) or not value or any(c in value for c in "/@:?# "):
        raise ValueError("domain requires hostname only")
    result=value.rstrip(".").encode("idna").decode("ascii").lower()
    if len(result)>253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",part) for part in result.split(".")):
        raise ValueError("invalid hostname")
    return result


def domain_match(candidate, domains, subdomains):
    try:candidate=host(candidate)
    except (ValueError,UnicodeError):return False
    return any(candidate==d or (subdomains and candidate.endswith("."+d)) for d in domains)


def strings(values, minimum=1):
    if not isinstance(values,list) or not values or any(not isinstance(v,str) or len(v)<minimum for v in values):
        raise ValueError("nonempty string list required")


def validate_policy(source):
    if not isinstance(source,dict) or type(source.get("schema_version")) is not int:
        raise ValueError("integer schema version required")
    legacy=source["schema_version"]==1
    if legacy:
        if set(source)!={"schema_version","canary_enabled","secrets_enabled","dictionary"} or any(type(source[k]) is not bool for k in ("canary_enabled","secrets_enabled")) or not isinstance(source["dictionary"],list):
            raise ValueError("invalid schema-1 policy")
        rules=[{"id":"test_canary","type":"exact_text","value":CANARY,"action":"block","enabled":source["canary_enabled"]}]
        for detector in ("credential_assignment","credential_field","private_key_block","supported_token_format"):
            rules.append({"id":detector,"type":"builtin","detector":detector,"action":"block","enabled":source["secrets_enabled"]})
        old_ids=set()
        for i,entry in enumerate(source["dictionary"]):
            if not isinstance(entry,dict) or set(entry)!={"id","values","boundary"} or not ident(entry["id"]) or entry["id"] in old_ids:raise ValueError("invalid legacy dictionary")
            old_ids.add(entry["id"])
            rules.append({"id":"dictionary-"+str(i),"type":"dictionary","enabled":True,"action":"block","matching":dict(MATCHING,boundary=entry["boundary"]),"entries":[{"id":entry["id"],"values":entry["values"]}]})
        source={"schema_version":2,"rules":rules}
    if source["schema_version"]!=2 or set(source)-{"schema_version","rules","inspection","replacements"} or not isinstance(source.get("rules"),list):
        raise ValueError("invalid schema-2 policy")
    limits=dict(LIMITS)
    extra=source.get("inspection",{})
    if not isinstance(extra,dict) or set(extra)-set(LIMITS):raise ValueError("invalid inspection settings")
    limits.update(extra)
    bounds={"max_input_bytes":(1024,10485760),"max_views":(16,10000),"max_json_depth":(4,128),"decode_depth":(0,3),"max_decoded_bytes":(1024,2097152)}
    for key,(lo,hi) in bounds.items():
        if type(limits[key]) is not int or not lo<=limits[key]<=hi:raise ValueError("invalid inspection limit")
    if not isinstance(limits["decoders"],list) or any(d not in ("percent","hex","base64") for d in limits["decoders"]) or len(set(limits["decoders"]))!=len(limits["decoders"]):raise ValueError("invalid decoders")
    compiled=[];ids=set()
    if len(source["rules"])>128:raise ValueError("too many rules")
    for original in source["rules"]:
        if not isinstance(original,dict):raise ValueError("rule must be object")
        r=dict(original);kind=r.get("type")
        common={"id","type","enabled","action"}
        if not ident(r.get("id")) or r["id"] in ids or type(r.get("enabled")) is not bool or r.get("action") not in ("block","audit"):raise ValueError("invalid rule controls")
        ids.add(r["id"])
        if kind=="builtin":
            if set(r)!=common|{"detector"} or r["detector"] not in BUILTINS:raise ValueError("unsupported builtin")
        elif kind=="exact_text":
            if set(r)!=common|{"value"} or not isinstance(r["value"],str) or not 1<=len(r["value"])<=8192:raise ValueError("invalid exact text")
        elif kind=="dictionary":
            if set(r)!=common|{"matching","entries"} or not isinstance(r["matching"],dict) or set(r["matching"])!=set(MATCHING):raise ValueError("invalid dictionary")
            m=r["matching"]
            if type(m["case_sensitive"]) is not bool or m["unicode_normalization"] not in ("NFKC","none") or m["whitespace"] not in ("collapse","preserve") or m["boundary"] not in ("whole_phrase","substring"):raise ValueError("invalid matching")
            if not isinstance(r["entries"],list) or not 1<=len(r["entries"])<=500:raise ValueError("invalid entries")
            seen=set();patterns=[]
            for entry in r["entries"]:
                if not isinstance(entry,dict) or set(entry)!={"id","values"} or not ident(entry["id"]) or entry["id"] in seen:raise ValueError("invalid entry")
                seen.add(entry["id"]);strings(entry["values"],3)
                for value in entry["values"]:
                    norm=normalize(value,m)
                    if not 3<=len(norm)<=8192:raise ValueError("invalid dictionary value")
                    pattern=re.escape(norm)
                    if m["boundary"]=="whole_phrase":pattern=r"(?<!\w)"+pattern+r"(?!\w)"
                    patterns.append((entry["id"],re.compile(pattern)))
            if len(patterns)>2000:raise ValueError("too many dictionary aliases")
            r["_patterns"]=patterns
        elif kind in ("url_domain","email"):
            required={"domains","include_subdomains"}|({"addresses"} if kind=="email" else set())
            if set(r)!=common|required or not isinstance(r["domains"],list) or type(r["include_subdomains"]) is not bool:raise ValueError("invalid domain rule")
            r["_domains"]=[host(d) for d in r["domains"]]
            if kind=="email":
                if not isinstance(r["addresses"],list) or any(not isinstance(a,str) or EMAIL.fullmatch(a) is None for a in r["addresses"]):raise ValueError("invalid address list")
                r["_addresses"]={a.casefold() for a in r["addresses"]}
            if not r["domains"] and (kind!="email" or not r["addresses"]):raise ValueError("empty domain/address rule")
        elif kind=="ip_network":
            if set(r)!=common|{"networks"}:raise ValueError("invalid network rule")
            strings(r["networks"])
            r["_networks"]=[ipaddress.ip_network(n,strict=True) for n in r["networks"]]
        elif kind=="field":
            if set(r)!=common|{"fields","values","case_sensitive"} or type(r["case_sensitive"]) is not bool:raise ValueError("invalid field rule")
            strings(r["fields"])
            if any(not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}",f) for f in r["fields"]):raise ValueError("invalid field name")
            if not isinstance(r["values"],list) or any(not isinstance(v,str) or not v for v in r["values"]):raise ValueError("invalid field values")
            r["_fields"]={re.sub(r"[^a-z]","",f.lower()) for f in r["fields"]}
            labels="|".join(re.escape(f).replace("_",r"[ _-]?").replace(r"\-",r"[ _-]?") for f in r["fields"])
            r["_prose_field"]=re.compile(r"(?i)\b(?:"+labels+r")\b[\"']?(?:\s*[:=]\s*|[ \t]+(?:is|equals)[ \t]+)"+CREDENTIAL_VALUE)
        elif kind=="resource":
            if set(r)!=common|{"values","case_sensitive"} or type(r["case_sensitive"]) is not bool:raise ValueError("invalid resource rule")
            strings(r["values"],3)
        else:raise ValueError("unsupported rule type")
        if legacy and kind=="dictionary":r["_legacy"]=True
        compiled.append(r)
    return {"schema_version":2,"source_schema_version":1 if legacy else 2,"rules":compiled,"inspection":limits,"replacements":compile_replacements(source.get("replacements",[]),ids)}


def base_views(text,limits):
    if len(text.encode("utf-8"))>limits["max_input_bytes"]:raise InspectionLimit("input limit")
    try:value=json.loads(text)
    except ValueError:return [("body.text",text,None)]
    result=[];stack=[("body",value,None,0)];nodes=0
    while stack:
        location,item,field,depth=stack.pop();nodes+=1
        if nodes>limits["max_views"] or depth>limits["max_json_depth"]:raise InspectionLimit("JSON limit")
        if isinstance(item,str):
            result.append((location,item,field))
            if item.lstrip().startswith(("{","[")):
                try:embedded=json.loads(item)
                except (ValueError,RecursionError):embedded=None
                if isinstance(embedded,(dict,list)):stack.append((location+".embedded_json",embedded,field,depth+1))
        elif isinstance(item,dict):
            for i,(key,val) in enumerate(item.items()):
                loc=location+".object["+str(i)+"]"
                result.append((loc+".key",key,None))
                stack.append((loc+".value",val,re.sub(r"[^a-z]","",key.casefold()),depth+1))
        elif isinstance(item,list):stack.extend((location+".array["+str(i)+"]",v,field,depth+1) for i,v in enumerate(item))
        elif field and item is not None:result.append((location,str(item),field))
        if len(result)>limits["max_views"]:raise InspectionLimit("view limit")
    result.append(("body.serialized",text,None))
    if len(result)>limits["max_views"]:raise InspectionLimit("view limit")
    return result


def decoded_views(views,limits):
    result=list(views);queue=[(loc,text,field,0) for loc,text,field in views];seen=set();total=0
    while queue:
        loc,text,field,depth=queue.pop()
        if depth>=limits["decode_depth"]:continue
        candidates=[]
        if "percent" in limits["decoders"] and re.search(r"%[0-9A-Fa-f]{2}",text):
            candidates.append(("percent",unquote_to_bytes(text)))
        if "hex" in limits["decoders"]:
            for match in re.finditer(r"(?<![0-9a-fA-F])[0-9a-fA-F]{16,8192}(?![0-9a-fA-F])",text):
                value=match.group()
                if len(value)%2==0:candidates.append(("hex",bytes.fromhex(value)))
        if "base64" in limits["decoders"]:
            for match in re.finditer(r"(?<![A-Za-z0-9_+/=-])[A-Za-z0-9_+/-]{16,8192}={0,2}(?![A-Za-z0-9_+/=-])",text):
                value=match.group()
                try:candidates.append(("base64",base64.b64decode(value+"="*((-len(value))%4),altchars=b"-_",validate=True)))
                except (ValueError,binascii.Error):pass
        for decoder,payload in candidates:
            total+=len(payload)
            if total>limits["max_decoded_bytes"]:raise InspectionLimit("decoded byte limit")
            try:decoded=payload.decode("utf-8",errors="strict")
            except UnicodeError:continue
            if not decoded or decoded==text:continue
            marker=(decoded,field,depth+1)
            if marker in seen:continue
            seen.add(marker)
            newloc=loc+".decoded_"+decoder
            # Parse decoded JSON too; no names/values are put into audit locations.
            for subloc,value,subfield in base_views(decoded,limits):
                item=(newloc+"."+subloc,value,subfield or field)
                result.append(item);queue.append((*item,depth+1))
                if len(result)>limits["max_views"]:raise InspectionLimit("decoded view limit")
    return result


def urls(text):
    for match in URL.finditer(text):
        value=match.group().rstrip(".,;)}]")
        # Preserve an IPv6 closing bracket when it ends the authority.
        if match.group().endswith("]") and ":[" in match.group():value=match.group()
        try:
            parsed=urlsplit(value)
            if parsed.hostname:yield parsed
        except ValueError:continue


def luhn(value):
    digits=[int(d) for d in value if d.isdigit() and d.isascii()]
    if not 13<=len(digits)<=19 or len(set(digits))<2:return False
    return sum((d*2-9 if d*2>9 else d*2) if i%2==1 else d for i,d in enumerate(reversed(digits)))%10==0


def iban(value):
    value=value.replace(" ","").upper()
    if not 15<=len(value)<=34:return False
    rearranged=value[4:]+value[:4];number="".join(str(ord(c)-55) if c.isalpha() else c for c in rearranged)
    return int(number)%97==1


def entropy(value):
    return -sum((n/len(value))*math.log2(n/len(value)) for n in Counter(value).values())


def builtin(detector,value,field):
    if detector=="credential_field":return field in FIELDS and credential(value)
    if detector=="credential_assignment":return explicit_credential(value)
    if detector=="private_key_block":return PRIVATE.search(value) is not None
    if detector=="supported_token_format":return TOKENS.search(value) is not None
    if detector=="connection_string":
        for parsed in urls(value):
            try:
                if parsed.password is not None and credential(parsed.password):return True
                if any(key.lower() in URI_SECRET_FIELDS and credential(val) for key,val in parse_qsl(parsed.query,keep_blank_values=True,max_num_fields=128)):return True
            except ValueError:continue
        return any(credential(m.group(1)) for m in ODBC.finditer(value))
    if detector=="hash_candidate":return HASH.search(value) is not None
    if detector=="entropy_candidate":return any(entropy(m.group())>=4.5 for m in RANDOM.finditer(value))
    if detector=="credit_card":return any(luhn(m.group()) for m in CARD.finditer(value))
    if detector=="iban":return iban_in_text(value)
    if detector=="phone_candidate":return PHONE.search(value) is not None
    return False


def inspect(policy,text):
    views=decoded_views(base_views(text,policy["inspection"]),policy["inspection"])
    matches=[]
    for rule in policy["rules"]:
        if not rule["enabled"]:continue
        for location,value,field in views:
            entry_id=None;kind=rule["type"]
            if kind=="exact_text":hit=rule["value"] in value
            elif kind=="dictionary":
                norm=normalize(value,rule["matching"])
                entry_id=next((eid for eid,p in rule["_patterns"] if p.search(norm)),None);hit=entry_id is not None
            elif kind=="builtin":hit=builtin(rule["detector"],value,field)
            elif kind=="url_domain":hit=any(domain_match(p.hostname,rule["_domains"],rule["include_subdomains"]) for p in urls(value))
            elif kind=="email":hit=any(m.group().casefold() in rule["_addresses"] or domain_match(m.group().rsplit("@",1)[1],rule["_domains"],rule["include_subdomains"]) for m in EMAIL.finditer(value))
            elif kind=="ip_network":
                hit=False
                candidates=[m.group() for m in IP_CANDIDATE.finditer(value)] + [p.hostname for p in urls(value)]
                for candidate in candidates:
                    try:address=ipaddress.ip_address(candidate.split("%",1)[0])
                    except ValueError:continue
                    if any(address.version==n.version and address in n for n in rule["_networks"]):hit=True;break
            elif kind=="field":
                current=value if rule["case_sensitive"] else value.casefold()
                allowed=rule["values"] if rule["case_sensitive"] else [v.casefold() for v in rule["values"]]
                hit=field in rule["_fields"] and credential(value) and (not allowed or current in allowed)
                if not hit:
                    for candidate in rule["_prose_field"].finditer(value):
                        item=next(v for v in candidate.groups() if v is not None)
                        normalized=item if rule["case_sensitive"] else item.casefold()
                        if credential(item) and normalized.casefold().rstrip(".!?") not in NATURAL_NONVALUES and (not allowed or normalized in allowed):
                            hit=True;break
            else:
                current=value if rule["case_sensitive"] else value.casefold()
                hit=any((v if rule["case_sensitive"] else v.casefold()) in current for v in rule["values"])
            if hit:
                match={"rule_id":"dictionary" if rule.get("_legacy") else rule["id"],"rule_type":kind,"action":rule["action"],"location":location}
                if kind=="builtin":match["detector"]=rule["detector"]
                if entry_id:match["entry_id"]=entry_id
                matches.append(match);break
    return matches


DEFAULT_REPLACEMENT_FIELDS = ("prompt", "content", "text", "title", "transformedContent", "instructions", "system", "description")

def compile_replacements(items, rule_ids=()):
    if not isinstance(items,list) or len(items)>128:raise ValueError("invalid replacements list")
    compiled=[];seen=set(rule_ids)
    allowed={"id","enabled","find","replace_with","case_sensitive","boundary","fields"}
    required=allowed-{"fields"}
    for item in items:
        if not isinstance(item,dict) or set(item)-allowed or not required<=set(item):raise ValueError("invalid replacement fields")
        if not ident(item["id"]) or item["id"] in seen:raise ValueError("invalid/duplicate replacement ID")
        seen.add(item["id"])
        if type(item["enabled"]) is not bool or type(item["case_sensitive"]) is not bool:raise ValueError("replacement flags must be boolean")
        if not isinstance(item["find"],str) or not 1<=len(item["find"])<=8192:raise ValueError("invalid replacement find")
        if not isinstance(item["replace_with"],str) or len(item["replace_with"])>8192:raise ValueError("invalid replacement value")
        if item["boundary"] not in ("whole_phrase","substring"):raise ValueError("invalid replacement boundary")
        fields=item.get("fields",list(DEFAULT_REPLACEMENT_FIELDS))
        if not isinstance(fields,list) or not fields or len(fields)>64 or any(not isinstance(f,str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}",f) for f in fields):raise ValueError("invalid replacement fields scope")
        expression=re.escape(item["find"])
        if item["boundary"]=="whole_phrase":expression=r"(?<!\w)"+expression+r"(?!\w)"
        compiled.append(dict(item,_pattern=re.compile(expression,0 if item["case_sensitive"] else re.IGNORECASE),_fields=set(fields)))
    return compiled

def replace_text(policy,text):
    """Bounded literal replacements; JSON keys and unselected fields are unchanged."""
    enabled=[r for r in policy.get("replacements",[]) if r["enabled"]]
    if not enabled:return text,[]
    limits=policy["inspection"];max_bytes=limits["max_input_bytes"]
    if len(text.encode("utf-8"))>max_bytes:raise InspectionLimit("replacement input limit")
    counts={r["id"]:0 for r in enabled};nodes=0;occurrences=0;extra_bytes=0
    def literal(value,field,plain=False):
        nonlocal occurrences,extra_bytes
        candidates=[]
        for order,r in enumerate(enabled):
            if not plain and field not in r["_fields"]:continue
            for m in r["_pattern"].finditer(value):
                candidates.append((m.start(),-len(m.group()),order,m.end(),r))
                if len(candidates)>limits["max_views"]:raise InspectionLimit("replacement match limit")
        candidates.sort(key=lambda x:x[:3]);parts=[];end=0
        for start,_,_,stop,r in candidates:
            if start<end:continue
            occurrences+=1
            if occurrences>limits["max_views"]:raise InspectionLimit("replacement occurrence limit")
            replacement=r["replace_with"]
            extra_bytes+=max(0,len(replacement.encode("utf-8"))-len(value[start:stop].encode("utf-8")))
            if extra_bytes>max_bytes:raise InspectionLimit("replacement expansion limit")
            parts.extend((value[end:start],replacement));end=stop;counts[r["id"]]+=1
        if not parts:return value
        parts.append(value[end:]);return "".join(parts)
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:raise ValueError("duplicate JSON keys not supported for replacement")
            result[key]=value
        return result
    def reject_constant(value):raise ValueError("nonfinite JSON value")
    def parse(value):return json.loads(value,object_pairs_hook=pairs,parse_constant=reject_constant)
    def visit(value,field=None,depth=0):
        nonlocal nodes
        nodes+=1
        if nodes>limits["max_views"] or depth>limits["max_json_depth"]:raise InspectionLimit("replacement structure limit")
        if isinstance(value,dict):return {k:visit(v,k,depth+1) for k,v in value.items()}
        if isinstance(value,list):return [visit(v,field,depth+1) for v in value]
        if isinstance(value,str):
            selected=any(field in r["_fields"] for r in enabled)
            if selected and value.lstrip().startswith(("{","[")):
                try:nested=parse(value)
                except json.JSONDecodeError:nested=None
                if isinstance(nested,(dict,list)):
                    before=sum(counts.values());changed=visit(nested,None,depth+1)
                    if sum(counts.values())!=before:return json.dumps(changed,ensure_ascii=False,separators=(",",":"),allow_nan=False)
                    return value
            return literal(value,field)
        return value
    try:body=parse(text)
    except json.JSONDecodeError:
        if text.lstrip().startswith(("{","[")):raise ValueError("malformed JSON replacement input")
        result=literal(text,None,plain=True)
    else:
        body=visit(body)
        result=json.dumps(body,ensure_ascii=False,separators=(",",":"),allow_nan=False) if any(counts.values()) else text
    if len(result.encode("utf-8"))>max_bytes:raise InspectionLimit("replacement output limit")
    return result,[{"rule_id":r["id"],"action":"replace","occurrences":counts[r["id"]]} for r in enabled if counts[r["id"]]]
