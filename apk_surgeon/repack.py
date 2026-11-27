"""Hardened APK repacking.

Two rules matter for every repack, whichever engine produced the APK:

* stale signature and Play metadata must be stripped before signing again;
* ``resources.arsc`` and uncompressed ``lib/**/*.so`` must stay stored, or the
  resulting APK is rejected by Android 11-16 (and breaks 16 KiB page mapping).
"""

import copy
import re
import shutil
import zipfile

SIGNATURE_SUFFIXES = ("sf", "rsa", "dsa", "ec", "mf")
PLAY_STAMP = "stamp-cert-sha256"


def is_stored_required(name):
    """True for entries that must stay uncompressed."""
    return name == "resources.arsc" or (name.startswith("lib/") and name.endswith(".so"))


def is_stale_metadata(name):
    """True for signature blocks and Play store stamps that must be dropped."""
    lowered = name.lower()
    if lowered == PLAY_STAMP:
        return True
    if not lowered.startswith("meta-inf/"):
        return False
    rest = lowered[len("meta-inf/"):]
    if "/" in rest:
        return False
    if rest.startswith("bndltool."):
        return True
    if rest == "manifest.mf":
        return True
    return bool(re.fullmatch(r"[^/]+\.(?:" + "|".join(SIGNATURE_SUFFIXES) + r")", rest))


def repack(source, dest, *, replace=None, strip_metadata=True):
    """Copy ``source`` to ``dest`` with hardened storage rules applied.

    ``replace`` maps member names to replacement bytes; the member keeps its
    original compression type.  All other entries are copied byte for byte.
    """
    replace = replace or {}
    written = set()
    with zipfile.ZipFile(source) as src, zipfile.ZipFile(dest, "w") as out:
        for item in src.infolist():
            if strip_metadata and is_stale_metadata(item.filename):
                continue
            entry = copy.copy(item)
            if is_stored_required(entry.filename):
                entry.compress_type = zipfile.ZIP_STORED
            if item.filename in replace:
                out.writestr(entry, replace[item.filename])
                written.add(item.filename)
                continue
            with src.open(item) as inp, out.open(entry, "w") as target:
                shutil.copyfileobj(inp, target)
            written.add(item.filename)
        for name, data in replace.items():
            if name in written:
                continue
            entry = zipfile.ZipInfo(name)
            entry.compress_type = zipfile.ZIP_STORED if is_stored_required(name) else zipfile.ZIP_DEFLATED
            out.writestr(entry, data)
    return dest


def stored_entries(apk):
    """Return the set of member names stored uncompressed in ``apk``."""
    with zipfile.ZipFile(apk) as archive:
        return {item.filename for item in archive.infolist() if item.compress_type == zipfile.ZIP_STORED}


def verify_storage(apk):
    """Raise when a required entry lost its ZIP_STORED flag."""
    with zipfile.ZipFile(apk) as archive:
        for item in archive.infolist():
            if is_stored_required(item.filename) and item.compress_type != zipfile.ZIP_STORED:
                raise ValueError(f"{item.filename} must be stored uncompressed")
    return True
