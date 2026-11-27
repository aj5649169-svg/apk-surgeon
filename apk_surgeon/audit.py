"""Opt-in power-user privacy audit patches.

``--trust-user-ca`` installs a network security config that trusts the user
certificate store (for mitmproxy, HTTP Toolkit or PCAPdroid on your own
device).  ``--allow-screenshots`` removes only unambiguous ``FLAG_SECURE``
(0x2000) window flag calls; dynamic bitmask expressions are left untouched.
"""

import re
from pathlib import Path

from lxml import etree

from . import layout
from .scanner import ANDROID, parse_manifest

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


def trust_user_ca(root):
    """Return changes installing or merging a user-CA network security config."""
    root = Path(root)
    manifest = layout.manifest(root)
    if manifest is None:
        raise ValueError("--trust-user-ca needs a decoded AndroidManifest.xml")
    tree = parse_manifest(manifest)
    if tree.docinfo.doctype:
        raise ValueError("Manifest DTD is unsupported")
    config = config_path(root)
    config.parent.mkdir(parents=True, exist_ok=True)
    application = tree.getroot().find("application")
    if application is None:
        raise ValueError("Manifest has no <application> element")
    package = tree.getroot().get("package", "")
    reference = f"@xml/{Path(CONFIG_NAME).stem}"
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
    changes = {manifest: etree.tostring(tree, encoding="UTF-8", xml_declaration=True).decode() + "\n"}
    changes[config] = CONFIG_TEMPLATE
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
