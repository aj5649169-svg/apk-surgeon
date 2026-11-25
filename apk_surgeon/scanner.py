import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from lxml import etree

ANDROID = "{http://schemas.android.com/apk/res/android}"
RULES = json.loads(Path(__file__).with_name("trackers.json").read_text())
CLASS = re.compile(r"(?m)^\.class[^\n]*?\s(L[^;\s]+;)[ \t]*(?:#.*)?$")
METHOD = re.compile(r"(?ms)^\.method[ \t]+([^\n]+)\n(.*?)^\.end method\b")


def parse_manifest(path):
    tree = etree.parse(str(path), etree.XMLParser(resolve_entities=False, no_network=True))
    if tree.docinfo.doctype:
        raise ValueError("Manifest DTD is unsupported")
    return tree


def components(tree):
    package = tree.getroot().get("package", "")
    for node in tree.xpath("/manifest/application/*"):
        name = node.get(ANDROID + "name", "")
        if node.tag in ("receiver", "service", "provider") and name:
            if name.startswith("."):
                name = package + name
            elif "." not in name:
                name = package + "." + name
            yield node, name


@dataclass
class Hit:
    classes: int = 0
    components: list = field(default_factory=list)
    hooks: list = field(default_factory=list)


def scan(root):
    hits = {r["name"]: Hit() for r in RULES}
    tree = parse_manifest(root / "AndroidManifest.xml")
    for node, name in components(tree):
        for rule in RULES:
            if name.startswith(rule["prefix"] + ".") or name in rule.get("providers", []):
                hits[rule["name"]].components.append(f"{node.tag}: {name}")
    for directory in root.glob("smali*"):
        if not re.fullmatch(r"smali(?:_classes\d+)?", directory.name):
            continue
        for rule in RULES:
            base = directory.joinpath(*rule["prefix"].split("."))
            for path in base.rglob("*.smali"):
                text = path.read_text(encoding="utf-8")
                cls = CLASS.search(text)
                if not cls or not cls[1].startswith("L" + rule["prefix"].replace(".", "/") + "/"):
                    continue
                hit = hits[rule["name"]]
                hit.classes += 1
                for method in METHOD.finditer(text):
                    sig = cls[1] + "->" + method[1].split("#")[0].split()[-1]
                    if sig in rule["hooks"]:
                        hit.hooks.append((path, sig))
    return {name: h for name, h in hits.items() if h.classes or h.components}


def exodus(root, database):
    """Match local, trusted Exodus code/network expressions against static evidence."""
    rows = json.loads(database.read_text(encoding="utf-8"))["trackers"]
    rules = [(r["name"], re.compile(r["code_signature"]) if r.get("code_signature") else None,
              re.compile(r["network_signature"],re.I) if r.get("network_signature") else None)
             for r in (rows.values() if isinstance(rows,dict) else rows)]
    found = set()
    for path in root.glob("smali*/**/*.smali"):
        text = path.read_text(encoding="utf-8")
        cls = CLASS.search(text)
        if not cls:
            continue
        descriptor = cls[1][1:-1]
        hosts = re.findall(r'(?i)\b(?:[a-z0-9-]+\.)+[a-z]{2,63}\b',text)
        for name, code, network in rules:
            if name in found:
                continue
            if ((code and (code.search(descriptor) or code.search(descriptor.replace("/","."))))
                    or (network and any(network.search(h) for h in hosts))):
                found.add(name)
    return sorted(found)
