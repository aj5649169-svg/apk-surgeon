"""Hardened APK repacking.

Two rules matter for every repack, whichever engine produced the APK:

* stale signature and Play metadata must be stripped before signing again;
* ``resources.arsc`` and uncompressed ``lib/**/*.so`` must stay stored, or the
  resulting APK is rejected by Android 11-16 (and breaks 16 KiB page mapping).
"""

import copy
import re
import shutil
import struct
import zipfile
from pathlib import Path

SIGNATURE_SUFFIXES = ("sf", "rsa", "dsa", "ec", "mf")
PLAY_STAMP = "stamp-cert-sha256"
_COPY_CHUNK = 1 << 20
_MASK_ENCRYPTED = 0x01
_MASK_DATA_DESCRIPTOR = 0x08


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


def _copy_raw_entry(raw_in, raw_in_size, out, item, entry):
    """Copy a raw ZIP payload byte-for-byte without decompressing/recompressing."""
    if (
        entry.is_dir()
        or entry.compress_type != item.compress_type
        or item.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
        or (item.flag_bits & _MASK_ENCRYPTED)
        or item.file_size >= zipfile.ZIP64_LIMIT
        or item.compress_size >= zipfile.ZIP64_LIMIT
        or not all(hasattr(out, attr) for attr in ("fp", "start_dir", "filelist", "NameToInfo", "_didModify"))
    ):
        return False
    raw_in.seek(item.header_offset)
    local_hdr = raw_in.read(30)
    if len(local_hdr) != 30 or local_hdr[:4] != b"PK\x03\x04":
        return False
    fn_len, ex_len = struct.unpack_from("<HH", local_hdr, 26)
    payload_off = item.header_offset + 30 + fn_len + ex_len
    if payload_off + item.compress_size > raw_in_size:
        return False
    out_entry = copy.copy(entry)
    out_entry.flag_bits &= ~_MASK_DATA_DESCRIPTOR
    out_entry.external_attr = out_entry.external_attr or (0o600 << 16)
    header = out_entry.FileHeader(zip64=False)
    out.fp.seek(out.start_dir)
    offset = out.fp.tell()
    if offset + len(header) + out_entry.compress_size > zipfile.ZIP64_LIMIT:
        return False
    out_entry.header_offset = offset
    out.fp.write(header)
    raw_in.seek(payload_off)
    remaining = out_entry.compress_size
    while remaining > 0:
        chunk = raw_in.read(min(_COPY_CHUNK, remaining))
        if not chunk:
            raise EOFError(f"Truncated ZIP payload for {item.filename}")
        out.fp.write(chunk)
        remaining -= len(chunk)
    out.start_dir = out.fp.tell()
    out._didModify = True
    out.filelist.append(out_entry)
    out.NameToInfo[out_entry.filename] = out_entry
    return True


def repack(source, dest, *, replace=None, strip_metadata=True, exclude=None):
    """Copy ``source`` to ``dest`` with hardened storage rules applied.

    ``replace`` maps member names to replacement bytes; ``exclude`` may filter
    unwanted entries by name.  Unmodified entries whose compression type stays
    unchanged are streamed raw without recompression.
    """
    replace = replace or {}
    written = set()
    src_path = Path(source)
    raw_size = src_path.stat().st_size
    with src_path.open("rb") as raw_in, zipfile.ZipFile(src_path) as src, zipfile.ZipFile(dest, "w") as out:
        for item in src.infolist():
            if strip_metadata and is_stale_metadata(item.filename):
                continue
            if exclude and exclude(item.filename):
                continue
            entry = copy.copy(item)
            if is_stored_required(entry.filename):
                entry.compress_type = zipfile.ZIP_STORED
            if item.filename in replace:
                out.writestr(entry, replace[item.filename])
                written.add(item.filename)
                continue
            if _copy_raw_entry(raw_in, raw_size, out, item, entry):
                written.add(item.filename)
                continue
            with src.open(item) as inp, out.open(entry, "w") as target:
                shutil.copyfileobj(inp, target, _COPY_CHUNK)
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
