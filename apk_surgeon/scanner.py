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


def ensure_android_namespace(root):
    """Ensure ``root`` declares ``xmlns:android`` so serialized attributes use ``android:``, not ``ns0:``."""
    android_uri = ANDROID[1:-1]
    if root.nsmap.get("android") == android_uri:
        return root
    rebuilt = etree.Element(root.tag, attrib=root.attrib, nsmap={**root.nsmap, "android": android_uri})
    rebuilt.text = root.text
    for child in list(root):
        rebuilt.append(child)
    return rebuilt


STARTUP_PROVIDER = "androidx.startup.InitializationProvider"
STARTUP_VALUES = frozenset({"androidx.startup", "@string/androidx_startup"})


def _resolve_component(package, name):
    if name.startswith("."):
        return package + name
    if "." not in name:
        return package + "." + name
    return name


def components(tree):
    package = tree.getroot().get("package", "")
    for node in tree.xpath("/manifest/application/*"):
        name = node.get(ANDROID + "name", "")
        if node.tag in ("receiver", "service", "provider") and name:
            yield node, _resolve_component(package, name)


def startup_initializers(tree):
    """Yield ``(meta_node, class_name)`` registered under AndroidX ``InitializationProvider``."""
    if tree is None:
        return
    package = tree.getroot().get("package", "")
    for node in tree.xpath("/manifest/application/provider"):
        pname = node.get(ANDROID + "name", "")
        if not pname or _resolve_component(package, pname) != STARTUP_PROVIDER:
            continue
        for meta in node.findall("meta-data"):
            mname = meta.get(ANDROID + "name", "")
            mval = meta.get(ANDROID + "value")
            if mname and (mval is None or mval in STARTUP_VALUES):
                yield meta, _resolve_component(package, mname)


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


def _rule_matches_component(rule, name):
    return (
        name.startswith(rule["prefix"] + ".")
        or name in rule.get("providers", ())
        or name in rule.get("initializers", ())
    )


def scan(root, *, manifest=True, recipe=None):
    effective = rules(recipe)
    hits = {rule["name"]: Hit() for rule in effective}
    tree = parse_manifest(layout.manifest(root)) if manifest and layout.manifest(root) else None
    if tree is not None:
        for node, name in components(tree):
            for rule in effective:
                if _rule_matches_component(rule, name):
                    hits[rule["name"]].components.append(f"{node.tag}: {name}")
        for _, name in startup_initializers(tree):
            for rule in effective:
                if _rule_matches_component(rule, name):
                    hits[rule["name"]].components.append(f"startup: {name}")
    for path in layout.smali_files(root):
        text = path.read_text(encoding="utf-8")
        cls = CLASS.search(text)
        if not cls:
            continue
        descriptor = cls[1]
        for rule in effective:
            prefix = rule["prefix"].replace(".", "/")
            if not (descriptor.startswith("L" + prefix + "/") or descriptor == "L" + prefix + ";"):
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
    try:
        payload = json.loads(database.read_text(encoding="utf-8"))
        rows = payload["trackers"]
        if not isinstance(rows, (dict, list)):
            raise TypeError("'trackers' must be an object or array")
        items = rows.values() if isinstance(rows, dict) else rows
        rules_ = [
            (
                str(row["name"]),
                re.compile(row["code_signature"]) if row.get("code_signature") else None,
                re.compile(row["network_signature"], re.I) if row.get("network_signature") else None,
            )
            for row in items
        ]
    except (OSError, json.JSONDecodeError, KeyError, TypeError, AttributeError, re.error) as error:
        raise ValueError(f"Invalid Exodus tracker DB {database}: {error}") from error
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
