import json
import re
from dataclasses import dataclass, field

from lxml import etree

from . import layout

ANDROID = "{http://schemas.android.com/apk/res/android}"
RULES = json.loads(layout.Path(__file__).with_name("trackers.json").read_text())
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


def rules(recipe=None):
    """Return the built-in rules plus any recipe-defined detection rules."""
    merged = [dict(rule) for rule in RULES]
    if not recipe:
        return merged
    for prefix in recipe.package_prefixes:
        merged.append({"name": f"Recipe: {prefix}", "prefix": prefix, "hooks": [],
                       "disable": [], "coverage": "detection-only"})
    grouped = {}
    for descriptor, signatures in recipe.methods.items():
        prefix = descriptor[1:-1].replace("/", ".")
        grouped.setdefault(prefix, set()).update(f"{descriptor}->{signature}" for signature in signatures)
    for prefix, hooks in sorted(grouped.items()):
        merged.append({"name": f"Recipe: {prefix}", "prefix": prefix, "hooks": sorted(hooks),
                       "disable": [], "coverage": "exact-method"})
    return merged


def scan(root, *, manifest=True, recipe=None):
    effective = rules(recipe)
    hits = {rule["name"]: Hit() for rule in effective}
    tree = parse_manifest(layout.manifest(root)) if manifest and layout.manifest(root) else None
    for node, name in (components(tree) if tree is not None else ()):
        for rule in effective:
            if name.startswith(rule["prefix"] + ".") or name in rule.get("providers", []):
                hits[rule["name"]].components.append(f"{node.tag}: {name}")
    for path in layout.smali_files(root):
        text = path.read_text(encoding="utf-8")
        cls = CLASS.search(text)
        if not cls:
            continue
        descriptor = cls[1]
        for rule in effective:
            prefix = rule["prefix"].replace(".", "/")
            if not descriptor.startswith("L" + prefix + "/"):
                continue
            hit = hits[rule["name"]]
            hit.classes += 1
            for method in METHOD.finditer(text):
                signature = descriptor + "->" + method[1].split("#")[0].split()[-1]
                if signature in rule["hooks"]:
                    hit.hooks.append((path, signature))
    return {name: hit for name, hit in hits.items() if hit.classes or hit.components}


def exodus(root, database):
    """Match local, trusted Exodus code/network expressions against static evidence."""
    rows = json.loads(database.read_text(encoding="utf-8"))["trackers"]
    rules_ = [(row["name"], re.compile(row["code_signature"]) if row.get("code_signature") else None,
               re.compile(row["network_signature"], re.I) if row.get("network_signature") else None)
              for row in (rows.values() if isinstance(rows, dict) else rows)]
    found = set()
    for path in layout.smali_files(root):
        text = path.read_text(encoding="utf-8")
        cls = CLASS.search(text)
        if not cls:
            continue
        descriptor = cls[1][1:-1]
        hosts = re.findall(r"(?i)\b(?:[a-z0-9-]+\.)+[a-z]{2,63}\b", text)
        for name, code, network in rules_:
            if name in found:
                continue
            if ((code and (code.search(descriptor) or code.search(descriptor.replace("/", "."))))
                    or (network and any(network.search(host) for host in hosts))):
                found.add(name)
    return sorted(found)
