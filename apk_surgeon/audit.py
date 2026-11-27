"""Opt-in power-user privacy audit patches.

``--trust-user-ca`` installs a network security config that trusts the user
certificate store (for mitmproxy, HTTP Toolkit or PCAPdroid on your own
device).  ``--allow-screenshots`` removes only unambiguous ``FLAG_SECURE``
(0x2000) window flag calls; dynamic bitmask expressions are left untouched.
"""

import io
import re
from pathlib import Path

from lxml import etree

from . import layout
from .scanner import ANDROID, ensure_android_namespace, parse_manifest

CONFIG_NAME = "apk_surgeon_network_security_config.xml"
CONFIG_TEMPLATE = """<?xml version="1.0" encoding="utf-8"?>
<!-- Added by APK Surgeon for personal traffic inspection on your own device. -->
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
"""
FLAG_SECURE = 0x2000
CONST_FLAG = re.compile(r"(?m)^(?P<indent>[ \t]*)const(?:/16)?[ \t]+(?P<register>v\d+),[ \t]*0x2000[ \t]*(?:#.*)?$")
WINDOW_CALL = re.compile(
    r"invoke-virtual[ \t]+\{[^}]*\b(?P<register>v\d+)\b[^}]*\},"
    r"[ \t]*Landroid/view/Window;->(?:setFlags\(II\)V|addFlags\(I\)V)"
)


def config_path(root):
    directory = layout.res_dir(root)
    if directory is None:
        directory = Path(root) / "res"
    return directory / "xml" / CONFIG_NAME


def merge_config(text):
    """Add system+user trust anchors to an existing network security config."""
    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    try:
        tree = etree.fromstring(text.encode("utf-8"), parser)
    except etree.XMLSyntaxError as error:
        raise ValueError(f"Existing network security config is not valid XML: {error}") from error
    if tree.tag != "network-security-config":
        raise ValueError(f"Existing config root is <{tree.tag}>, expected <network-security-config>")
    base = tree.find("base-config")
    if base is None:
        base = etree.SubElement(tree, "base-config")
        base.set("cleartextTrafficPermitted", "true")
    anchors = base.find("trust-anchors")
    if anchors is None:
        anchors = etree.SubElement(base, "trust-anchors")
    present = {node.get("src") for node in anchors.findall("certificates")}
    for source in ("system", "user"):
        if source not in present:
            etree.SubElement(anchors, "certificates").set("src", source)
    return etree.tostring(tree, encoding="UTF-8", xml_declaration=True).decode() + "\n"


def _apkeditor_public_change(res_root, stem):
    """Register ``@xml/<stem>`` in APKEditor's ``values/public.xml`` when needed."""
    if res_root.parent.parent.name != "resources":
        return None
    pub_path = res_root / "values" / "public.xml"
    if not pub_path.is_file():
        return None
    tree = etree.parse(str(pub_path), etree.XMLParser(resolve_entities=False, no_network=True))
    if tree.docinfo.doctype:
        raise ValueError("public.xml DTD is unsupported")
    root = tree.getroot()
    for node in root.findall("public"):
        if node.attrib.get("type") == "xml" and node.attrib.get("name") == stem:
            return None
    ids = []
    xml_ids = []
    for node in root.findall("public"):
        raw = node.attrib.get("id")
        if not raw:
            continue
        try:
            parsed = int(raw, 16)
        except ValueError:
            continue
        ids.append(parsed)
        if node.attrib.get("type") == "xml":
            xml_ids.append(parsed)
    pkg_raw = root.attrib.get("id")
    if pkg_raw:
        pkg_prefix = (int(pkg_raw, 16) & 0xFF) << 24
    elif ids:
        pkg_prefix = ids[0] & 0xFF000000
    else:
        pkg_prefix = 0x7F000000
    if xml_ids:
        next_id = max(xml_ids) + 1
    else:
        used_types = {(val >> 16) & 0xFF for val in ids}
        next_type = next((t for t in range(1, 256) if t not in used_types), None)
        if next_type is None:
            raise ValueError("No free Android resource type ID available in public.xml")
        next_id = pkg_prefix | (next_type << 16)
    entry = etree.SubElement(root, "public", id=f"0x{next_id:08x}", type="xml", name=stem)
    entry.tail = "\n"
    return pub_path, etree.tostring(root, encoding="UTF-8", xml_declaration=True).decode() + "\n"


def trust_user_ca(root, *, manifest_text=None):
    """Return changes installing or merging a user-CA network security config."""
    root = Path(root)
    manifest = layout.manifest(root)
    if manifest is None:
        raise ValueError("--trust-user-ca needs a decoded AndroidManifest.xml")
    if manifest_text is not None:
        tree = etree.parse(
            io.BytesIO(manifest_text.encode("utf-8")),
            etree.XMLParser(resolve_entities=False, no_network=True),
        )
    else:
        tree = parse_manifest(manifest)
    if tree.docinfo.doctype:
        raise ValueError("Manifest DTD is unsupported")
    res_root = layout.res_dir(root) or (root / "res")
    config = res_root / "xml" / CONFIG_NAME
    root_el = ensure_android_namespace(tree.getroot())
    application = root_el.find("application")
    if application is None:
        raise ValueError("Manifest has no <application> element")
    package = root_el.get("package", "")
    stem = Path(CONFIG_NAME).stem
    reference = f"@xml/{stem}"
    existing = application.get(ANDROID + "networkSecurityConfig")
    if existing:
        match = re.fullmatch(r"@xml/([A-Za-z0-9_.]+)", existing)
        if not match:
            raise ValueError(
                f"Manifest references {existing!r}, which is not an @xml/ resource. Remove the attribute before "
                "using --trust-user-ca."
            )
        target = config.parent / (match.group(1) + ".xml")
        if not target.is_file():
            raise ValueError(
                f"Manifest references {existing}, but {target} is not in the decoded resources. Decode resources "
                "(drop --smali-only and avoid APKEditor -t json/raw) before using --trust-user-ca."
            )
        return {target: merge_config(target.read_text(encoding="utf-8"))}, package
    application.set(ANDROID + "networkSecurityConfig", reference)
    changes = {manifest: etree.tostring(root_el, encoding="UTF-8", xml_declaration=True).decode() + "\n"}
    changes[config] = CONFIG_TEMPLATE
    public_edit = _apkeditor_public_change(res_root, stem)
    if public_edit is not None:
        pub_path, pub_text = public_edit
        changes[pub_path] = pub_text
    return changes, package


def allow_screenshots_text(text):
    """Neutralize literal FLAG_SECURE window flags in one smali file."""
    return _flag_secure_patch(text)


def _flag_secure_patch(text):
    """Neutralize literal FLAG_SECURE constants used by Window flag calls.

    Only the immediately following instruction counts.  If anything else
    touches the register first the expression is dynamic and is left alone.
    """
    lines = text.splitlines(keepends=True)
    count = 0
    for index, line in enumerate(lines):
        match = CONST_FLAG.match(line.rstrip("\n"))
        if not match:
            continue
        following = index + 1
        while following < len(lines) and (not lines[following].strip()
                                          or lines[following].lstrip().startswith("#")):
            following += 1
        if following >= len(lines):
            continue
        call = WINDOW_CALL.match(lines[following].strip())
        if not call or call.group("register") != match.group("register"):
            continue
        replacement = line.replace("0x2000", "0x0", 1)
        if replacement != line:
            lines[index] = replacement
            count += 1
    return "".join(lines), count


def allow_screenshots(root):
    """Return smali changes that drop literal FLAG_SECURE window flags."""
    changes = {}
    total = 0
    for path in layout.smali_files(root):
        original = path.read_text(encoding="utf-8")
        if "0x2000" not in original:
            continue
        edited, count = allow_screenshots_text(original)
        if count:
            changes[path] = edited
            total += count
    return changes, total
