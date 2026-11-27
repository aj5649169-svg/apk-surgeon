import difflib
import re
import shutil
from collections import defaultdict

from lxml import etree

from . import layout
from .scanner import ANDROID, METHOD, RULES, components, parse_manifest


def patch_smali(text, signatures):
    def replace(m):
        flags = m[1].split("#")[0].split()
        sig = flags[-1]
        if sig not in signatures or sig.startswith("<") or {"abstract", "native"} & set(flags[:-1]):
            return m[0]
        if not sig.endswith((")V", ")Z")):
            return m[0]
        locals_line = re.search(r"(?m)^([ \t]*)\.locals[ \t]+(\d+)[ \t]*(?:#[^\n]*)?$", m[2])
        if not re.fullmatch(r"[^\s()<>]+\((?:\[*(?:[ZBCSIFJD]|L[^;()\s]+;))*\)[VZ]", sig):
            return m[0]
        if not locals_line or len(re.findall(r"(?m)^\s*\.(?:registers|locals)\b", m[2])) != 1:
            return m[0]
        if int(locals_line[2]) > 65535 or ".method " in m[2]:
            return m[0]
        value = sig.endswith(")Z")
        if value and int(locals_line[2]) == 0:
            # v0 aliases a parameter here. Growing the register frame can invalidate
            # existing v-register references and instruction operand widths.
            return m[0]
        indent = locals_line[1]
        stub = ("const/4 v0, 0x0\n" + indent + "return v0") if value else "return-void"
        pos = m.start(2) - m.start() + locals_line.end()
        if m[0][pos:].lstrip().startswith(stub):
            return m[0]
        return m[0][:pos] + "\n" + indent + stub + m[0][pos:]
    return METHOD.sub(replace, text)


PROVIDERS = {
    "com.google.firebase.provider.FirebaseInitProvider",
    "com.facebook.internal.FacebookInitProvider",
    *(provider for rule in RULES for provider in rule.get("providers", [])),
}
AD_PERMISSIONS = {
    "com.google.android.gms.permission.AD_ID",
    "android.permission.ACCESS_ADSERVICES_AD_ID",
    "android.permission.ACCESS_ADSERVICES_ATTRIBUTION",
}


def plan(root, hits, strip_ad_permissions=False, disable_providers=False, *, manifest=True, recipe=None):
    changes = {}
    if manifest and layout.manifest(root):
        path = layout.manifest(root)
        tree = parse_manifest(path)
        allowed = {component for rule in RULES for component in rule["disable"]}
        if recipe:
            allowed.update(recipe.disable_components)
        changed = False
        for node, name in components(tree):
            selected = name in allowed and node.tag in ("receiver", "service")
            selected |= disable_providers and node.tag == "provider" and name in PROVIDERS
            if selected and node.get(ANDROID + "enabled") != "false":
                node.set(ANDROID + "enabled", "false")
                changed = True
        if strip_ad_permissions:
            for permission in tree.xpath("/manifest/uses-permission | /manifest/uses-permission-sdk-23"):
                if permission.get(ANDROID + "name") in AD_PERMISSIONS:
                    permission.getparent().remove(permission)
                    changed = True
        if changed:
            changes[path] = etree.tostring(tree, encoding="UTF-8", xml_declaration=True).decode() + "\n"
    files = defaultdict(set)
    for hit in hits.values():
        for path, signature in hit.hooks:
            files[path].add(signature.split("->")[1])
    for path, methods in files.items():
        original = path.read_text(encoding="utf-8")
        edited = patch_smali(original, methods)
        if edited != original:
            changes[path] = edited
    return changes


def diff(root, changes):
    for path, new in changes.items():
        if isinstance(new, bytes):
            continue
        name = path.relative_to(root).as_posix()
        yield from difflib.unified_diff(path.read_text(encoding="utf-8").splitlines(True),
                                        new.splitlines(True), fromfile="a/" + name, tofile="b/" + name)


def apply(root, changes, backup):
    for path, text in changes.items():
        if isinstance(text, bytes):
            continue
        dest = backup / (str(path.relative_to(root)) + ".bak")
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dest)
        path.write_text(text, encoding="utf-8")
