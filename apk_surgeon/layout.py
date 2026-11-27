"""Locate files in decoded APK trees produced by Apktool or APKEditor.

Apktool writes ``AndroidManifest.xml`` at the decode root and puts DEX
disassembly in ``smali/``, ``smali_classes2/`` and so on.  APKEditor also
writes the manifest at the root but disassembles each DEX under
``smali/classes/``, ``smali/classes2/`` and so on.  Everything here is a
tolerant lookup so callers never hard-code either layout.
"""

import re
from pathlib import Path

APKTOOL_SMALI = re.compile(r"smali(?:_classes(\d+))?")
APKEDITOR_SMALI = re.compile(r"classes(\d*)")
MANIFEST = "AndroidManifest.xml"


def manifest(root):
    """Return the decoded AndroidManifest.xml path or None."""
    direct = Path(root) / MANIFEST
    if direct.is_file():
        return direct
    for candidate in sorted(Path(root).glob("*/" + MANIFEST)):
        if candidate.is_file():
            return candidate
    return None


def smali_dirs(root):
    """Return every directory that contains smali source for the decoded APK."""
    root = Path(root)
    found = set()
    for child in root.iterdir():
        if not child.is_dir():
            continue
        if child.name == "smali" or APKTOOL_SMALI.fullmatch(child.name):
            found.add(child)
    # APKEditor keeps its dex folders one level below smali/; the parent
    # directory already covers them, and adding both would duplicate files.
    return sorted(found)


def dex_number(root, path):
    """Return the 1-based classesN.dex index a smali file came from."""
    try:
        parts = Path(path).relative_to(root).parts
    except ValueError:
        return 1
    if not parts:
        return 1
    match = APKTOOL_SMALI.fullmatch(parts[0])
    if match and parts[0] != "smali":
        return int(match.group(1) or 1)
    if parts[0] == "smali" and len(parts) > 1:
        match = APKEDITOR_SMALI.fullmatch(parts[1])
        if match:
            return int(match.group(1) or 1)
    return 1


def smali_files(root, dexes=None):
    """Yield every smali file, optionally limited to the given dex numbers."""
    for directory in smali_dirs(root):
        for path in directory.rglob("*.smali"):
            if dexes is None or dex_number(root, path) in dexes:
                yield path


def res_dir(root):
    """Return the resource root used by the decoded tree, if any."""
    root = Path(root)
    direct = root / "res"
    if direct.is_dir():
        return direct
    for candidate in sorted(root.glob("*/res")):
        if candidate.is_dir():
            return candidate
    return None
