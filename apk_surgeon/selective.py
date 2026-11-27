"""Selective multi-DEX patching.

Only the ``classesN.dex`` files that contain a matched tracker class or
telemetry host are disassembled, patched and reassembled.  All other DEX files,
``resources.arsc``, ``res/`` and native libraries are copied byte for byte,
including their ZIP_STORED flags.

The trick that keeps this pure-Python and engine-agnostic: build a trimmed APK
containing a single DEX, let Apktool disassemble just that file, patch the
smali, rebuild, then splice the single rebuilt ``classes.dex`` back into a copy
of the original archive under its original member name.
"""

import shutil
import zipfile
from pathlib import Path

from . import dex_scanner, engines, repack

DEX_NAME = dex_scanner.DEX_NAME


class SelectiveError(ValueError):
    """Selective patching could not be completed; fall back to a full decode."""


def dex_candidates(apk, needles):
    """Return the dex member names that mention any needle."""
    try:
        return sorted(dex_scanner.find_matches(apk, needles))
    except (OSError, zipfile.BadZipFile, dex_scanner.DexError) as error:
        raise SelectiveError(str(error)) from error


def _trimmed(source, dest, keep):
    """Copy ``source`` to ``dest`` keeping only one classes*.dex."""
    with zipfile.ZipFile(source) as src, zipfile.ZipFile(dest, "w") as out:
        for item in src.infolist():
            if DEX_NAME.fullmatch(item.filename) and item.filename != keep:
                continue
            if repack.is_stale_metadata(item.filename):
                continue
            entry = item
            with src.open(item) as inp, out.open(entry, "w") as target:
                shutil.copyfileobj(inp, target)
    return dest


def _single_smali_root(root):
    directories = [path for path in Path(root).iterdir() if path.is_dir()]
    smali = [path for path in directories if path.name == "smali" or path.name.startswith("smali")]
    if not smali:
        raise SelectiveError("Apktool produced no smali directory for the selected DEX")
    return smali[0]


def patch_dex(apk, work, dex_name, transform):
    """Patch one DEX of ``apk`` and return a new APK path.

    ``transform`` receives ``(path, text)`` for every smali file and returns the
    edited text (or the original text to leave it alone).  Returns ``(path,
    changed_files, replacements)``; ``path`` is the original when nothing
    changed.
    """
    work = Path(work)
    work.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(apk) as archive:
        if dex_name not in archive.namelist():
            raise SelectiveError(f"{dex_name} not found in {apk}")
        try:
            header = dex_scanner.parse_header(dex_scanner._read_dex(archive, dex_name))
        except dex_scanner.DexError as error:
            raise SelectiveError(f"{dex_name} is unreadable: {error}") from error
        if header.version >= 41:
            raise SelectiveError(f"{dex_name} uses DEX 041 container format, unsupported in selective mode")
    trimmed = _trimmed(apk, work / "trimmed.apk", dex_name)
    root = work / "dex"
    if root.exists():
        shutil.rmtree(root)
    engines.decode_apktool(trimmed, root, no_res=True)
    smali_root = _single_smali_root(root)
    changed = []
    replacements = []
    for path in sorted(smali_root.rglob("*.smali")):
        original = path.read_text(encoding="utf-8")
        edited, found = transform(path, original)
        if found:
            replacements.extend(found)
        if edited != original:
            path.write_text(edited, encoding="utf-8")
            changed.append(path.relative_to(root).as_posix())
    if not changed:
        return apk, [], []
    built = work / "built.apk"
    engines.rebuild_apktool(root, built)
    with zipfile.ZipFile(built) as archive:
        names = set(archive.namelist())
        member = dex_name if dex_name in names else "classes.dex"
        if member not in names:
            raise SelectiveError(f"Rebuilt APK has no {dex_name} or classes.dex")
        rebuilt = archive.read(member)
    try:
        dex_scanner.parse_header(rebuilt)
    except dex_scanner.DexError as error:
        raise SelectiveError(f"Rebuilt DEX is invalid: {error}") from error
    output = work / f"selective-{Path(dex_name).stem}.apk"
    with zipfile.ZipFile(apk) as archive:
        if dex_name not in archive.namelist():
            raise SelectiveError(f"{dex_name} vanished from the APK")
        repack.repack(apk, output, replace={dex_name: rebuilt})
    return output, changed, replacements
