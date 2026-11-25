import difflib
import re
import shutil
from collections import defaultdict

from lxml import etree

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
        if not locals_line:
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


def plan(root, hits):
    changes = {}
    path = root / "AndroidManifest.xml"
    tree = parse_manifest(path)
    allowed = {c for r in RULES for c in r["disable"]}
    changed = False
    for node, name in components(tree):
        if name in allowed and node.tag in ("receiver", "service") and node.get(ANDROID+"enabled") != "false":
            node.set(ANDROID+"enabled", "false")
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
        name = path.relative_to(root).as_posix()
        yield from difflib.unified_diff(path.read_text(encoding="utf-8").splitlines(True),
            new.splitlines(True), fromfile="a/"+name, tofile="b/"+name)


def apply(root, changes, backup):
    for path, text in changes.items():
        dest = backup / (str(path.relative_to(root)) + ".bak")
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dest)
        path.write_text(text, encoding="utf-8")
