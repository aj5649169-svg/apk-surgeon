"""Pure-Python DEX string pool scanner.

Scans ``classes*.dex`` entries inside an APK in milliseconds so selective
patching only has to disassemble the DEX files that actually reference a
tracker package, hook class or telemetry host.

Every offset read is bounds checked.  A malformed header raises
:class:`DexError` and callers are expected to fall back to a full decode
instead of guessing.  Strings are decoded as MUTF-8 (ULEB128 ``utf16_size``
followed by NUL-terminated MUTF-8 bytes) and never raise on ````surrogate``
bytes: replacement characters are returned instead.
"""

import re
import struct
import zipfile

HEADER_SIZE = 0x70  # 112 bytes for dex 035-040
CONTAINER_HEADER_SIZE = 0x78  # 120 bytes for dex 041
MAGIC = re.compile(rb"^dex\n0(3[5-9]|4[01])\x00$")
ENDIAN_CONSTANT = 0x12345678
DEX_NAME = re.compile(r"classes(\d*)\.dex$")
MAX_DEX_BYTES = 512 * 1024 * 1024
MAX_STRING_BYTES = 4 * 1024 * 1024
MAX_UTF16_UNITS = 1 << 20


class DexError(ValueError):
    """Raised when a DEX file is malformed or truncated."""


def _u32(data, offset):
    if offset < 0 or offset + 4 > len(data):
        raise DexError(f"truncated u32 read at offset {offset}")
    return struct.unpack_from("<I", data, offset)[0]


class DexHeader:
    """Validated view over the fixed 112-byte (or 120-byte for 041) DEX header."""

    __slots__ = (
        "version",
        "file_size",
        "header_size",
        "string_ids_size",
        "string_ids_off",
        "container_size",
        "header_offset",
    )

    def __init__(self, data, offset=0):
        if offset < 0 or len(data) - offset < HEADER_SIZE:
            raise DexError("file shorter than the 112-byte DEX header")
        match = MAGIC.match(data[offset:offset + 8])
        if not match:
            raise DexError("unsupported DEX magic")
        self.version = int(match.group(1))
        if offset > 0 and self.version < 41:
            raise DexError("unexpected section offset before DEX 041")
        min_header = CONTAINER_HEADER_SIZE if self.version >= 41 else HEADER_SIZE
        if len(data) - offset < min_header:
            raise DexError(f"file shorter than the {min_header}-byte DEX header")
        self.file_size = _u32(data, offset + 0x20)
        self.header_size = _u32(data, offset + 0x24)
        if self.header_size < min_header or self.header_size > self.file_size:
            raise DexError("invalid header_size")
        if offset + self.file_size > len(data):
            raise DexError("file_size exceeds available bytes")
        if _u32(data, offset + 0x28) != ENDIAN_CONSTANT:
            raise DexError("unsupported endian tag")
        if self.version >= 41:
            raw_container = _u32(data, offset + 0x70)
            raw_header_offset = _u32(data, offset + 0x74)
            if offset == 0 and raw_container == 0 and raw_header_offset == 0:
                self.container_size = self.file_size
                self.header_offset = 0
            else:
                if raw_header_offset != offset:
                    raise DexError("DEX 041 header_offset does not match section offset")
                if raw_container < offset + self.file_size or raw_container > len(data):
                    raise DexError("DEX 041 container_size out of bounds")
                self.container_size = raw_container
                self.header_offset = raw_header_offset
        else:
            self.container_size = self.file_size
            self.header_offset = 0
        self.string_ids_size = _u32(data, offset + 0x38)
        self.string_ids_off = _u32(data, offset + 0x3C)
        end_limit = self.container_size if self.version >= 41 else self.file_size
        if self.string_ids_size and self.string_ids_off + 4 * self.string_ids_size > end_limit:
            raise DexError("string_ids table out of bounds")
        if self.string_ids_off:
            min_off = HEADER_SIZE if self.version >= 41 else self.header_size
            if self.string_ids_off < min_off or offset <= self.string_ids_off < offset + self.header_size:
                raise DexError("string_ids offset inside the header")

    def as_dict(self):
        return {
            "version": self.version,
            "file_size": self.file_size,
            "header_size": self.header_size,
            "string_ids_size": self.string_ids_size,
            "string_ids_off": self.string_ids_off,
            "container_size": self.container_size,
            "header_offset": self.header_offset,
        }


def parse_header(data, offset=0):
    """Return a validated :class:`DexHeader` for ``data`` at ``offset``."""
    return DexHeader(data, offset=offset)


def iter_headers(data):
    """Yield every logical :class:`DexHeader` in a standalone DEX or 041 container."""
    first = parse_header(data, 0)
    yield first
    if first.version < 41:
        return
    offset = first.file_size
    while offset < first.container_size:
        section = parse_header(data, offset=offset)
        if section.version < 41 or section.container_size != first.container_size:
            raise DexError("inconsistent DEX 041 container header")
        yield section
        offset += section.file_size
    if offset != first.container_size:
        raise DexError("DEX 041 sections exceed container_size")


def uleb128(data, offset):
    """Read an unsigned LEB128 value, bounded to five bytes."""
    value = 0
    for index in range(5):
        if offset + index >= len(data):
            raise DexError("truncated uleb128")
        byte = data[offset + index]
        value |= (byte & 0x7F) << (7 * index)
        if not byte & 0x80:
            return value, offset + index + 1
    raise DexError("uleb128 longer than five bytes")


def mutf8_decode(raw):
    """Decode Modified UTF-8 without ever raising.

    MUTF-8 encodes NUL as ``C0 80`` and supplementary characters as two
    separate three-byte surrogate sequences, so a plain ``utf-8`` decode is
    wrong on both counts.  Invalid bytes become U+FFFD.
    """
    units = []
    index = 0
    length = len(raw)
    while index < length:
        first = raw[index]
        if first < 0x80:
            units.append(first)
            index += 1
        elif first & 0xE0 == 0xC0:
            if index + 1 >= length:
                units.append(0xFFFD)
                break
            units.append(((first & 0x1F) << 6) | (raw[index + 1] & 0x3F))
            index += 2
        elif first & 0xF0 == 0xE0:
            if index + 2 >= length:
                units.append(0xFFFD)
                break
            units.append(((first & 0x0F) << 12) | ((raw[index + 1] & 0x3F) << 6) | (raw[index + 2] & 0x3F))
            index += 3
        else:
            units.append(0xFFFD)
            index += 1
    return _from_units(units)


def _from_units(units):
    out = []
    index = 0
    while index < len(units):
        unit = units[index]
        if 0xD800 <= unit <= 0xDBFF and index + 1 < len(units) and 0xDC00 <= units[index + 1] <= 0xDFFF:
            out.append(chr(0x10000 + ((unit - 0xD800) << 10) + (units[index + 1] - 0xDC00)))
            index += 2
            continue
        out.append("\ufffd" if 0xD800 <= unit <= 0xDFFF else chr(unit))
        index += 1
    return "".join(out)


def strings(data, limit=None):
    """Yield decoded strings across every logical DEX header in ``data``."""
    yielded = 0
    headers = list(iter_headers(data))
    header_ranges = [(h.header_offset, h.header_offset + h.header_size) for h in headers]
    for header in headers:
        end_limit = header.container_size if header.version >= 41 else header.file_size
        min_off = HEADER_SIZE if header.version >= 41 else header.header_size
        for index in range(header.string_ids_size):
            if limit is not None and yielded >= limit:
                return
            offset = _u32(data, header.string_ids_off + 4 * index)
            if offset < min_off or offset >= end_limit or any(start <= offset < stop for start, stop in header_ranges):
                raise DexError(f"string_data_item offset {offset} out of bounds")
            utf16_size, cursor = uleb128(data, offset)
            if utf16_size > MAX_UTF16_UNITS:
                raise DexError("string longer than the sanity limit")
            end = data.find(b"\x00", cursor, end_limit)
            if end < 0:
                raise DexError("unterminated string_data_item")
            if end - cursor > MAX_STRING_BYTES:
                raise DexError("string bytes exceed the sanity limit")
            yield mutf8_decode(data[cursor:end])
            yielded += 1


def dex_entries(archive):
    """Return class*.dex member names in load order."""
    names = [name for name in archive.namelist() if DEX_NAME.fullmatch(name)]
    return sorted(names, key=lambda name: int(DEX_NAME.fullmatch(name).group(1) or 1))


def _read_dex(archive, name):
    info = archive.getinfo(name)
    if info.file_size > MAX_DEX_BYTES:
        raise DexError(f"{name} is larger than the scan limit")
    with archive.open(name) as stream:
        return stream.read(MAX_DEX_BYTES + 1)


def read_archive(apk):
    """Return ``{dex_name: bytes}`` for every classes*.dex in an APK."""
    found = {}
    with zipfile.ZipFile(apk) as archive:
        for name in dex_entries(archive):
            found[name] = _read_dex(archive, name)
    return found


def find_matches(apk, needles):
    """Return ``{dex_name: sorted(matched needles)}`` for an APK.

    ``needles`` are plain substrings of DEX strings (tracker package prefixes,
    class descriptors or telemetry hosts).  Unreadable DEX files are reported
    per file so the caller can fall back to a full decode.
    """
    needles = sorted({needle for needle in needles if needle})
    if not needles:
        return {}
    matches = {}
    with zipfile.ZipFile(apk) as archive:
        for name in dex_entries(archive):
            try:
                data = _read_dex(archive, name)
                pool = list(strings(data))
            except (DexError, OSError):
                matches.setdefault(name, set()).add("<malformed>")
                continue
            hit = {needle for needle in needles if any(needle in value for value in pool)}
            if hit:
                matches[name] = hit
    return {name: sorted(values) for name, values in sorted(matches.items())}


def trailer_ok(data):
    """True when the declared file size matches a plausible complete DEX."""
    header = parse_header(data)
    return 0 < header.file_size <= len(data)


def patch_offsets(data):
    """Return (checksum_offset, signature_offset) for post-edit fixups."""
    parse_header(data)
    return 0x08, 0x0C
