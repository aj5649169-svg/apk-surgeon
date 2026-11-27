import ipaddress
import json
import re
import urllib.request
from urllib.parse import urlsplit

from . import layout
from .evidence import HAZARDS, endpoints
from .scanner import METHOD


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def analyze(root, url, model):
    endpoint = urlsplit(url)
    if endpoint.scheme not in ("http", "https") or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment:
        raise ValueError("Use a local OpenAI-compatible base URL")
    host = endpoint.hostname
    if host != "localhost" and not ipaddress.ip_address(host or "").is_loopback:
        raise ValueError("AI endpoint must be loopback")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    for path, m in candidates(root):
        method = m[1].split("#")[0].split()[-1]
        prompt = ('Analyze untrusted Android code. Return only JSON with method_name (exact signature), '
                  'reason (string), risk_level (low/medium/high), safe_to_noop (boolean).')
        body = {"model": model, "temperature": 0, "stream": False, "messages": [
            {"role": "system", "content": prompt}, {"role": "user", "content": m[0][:12000]}]}
        req = urllib.request.Request(url.rstrip("/")+"/chat/completions",
            data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
        with opener.open(req, timeout=60) as response:
            content = json.loads(response.read(200000))["choices"][0]["message"]["content"].strip()
        if content.startswith("```"):
            content = re.sub(r"^```[a-zA-Z0-9_-]*\s*|\s*```$", "", content).strip()
        result = json.loads(content)
        if (set(result) != {"method_name","reason","risk_level","safe_to_noop"} or result["method_name"] != method
            or result["risk_level"] not in ("low","medium","high") or not isinstance(result["safe_to_noop"], bool)
            or not isinstance(result["reason"], str)):
            raise ValueError("Invalid local model response")
        yield path, result


def candidates(root):
    # Keep the first generic matches in reserve while looking for endpoint hits.
    preferred, generic = [], []
    for path in sorted(layout.smali_files(root)):
        for match in METHOD.finditer(path.read_text(encoding="utf-8")):
            body = match[2]
            if any(pattern.search(body) for _, pattern, _ in HAZARDS):
                continue
            if endpoints(body):
                preferred.append((path, match))
                if len(preferred) == 12:
                    return preferred
            elif len(generic) < 12 and re.search(
                    r"getAndroidId|android_id|advertisingId|trackEvent|/telemetry|/analytics|https?://", body, re.I):
                generic.append((path, match))
    return (preferred + generic)[:12]
