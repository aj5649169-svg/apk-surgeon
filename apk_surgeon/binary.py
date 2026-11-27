"""Pure-Python binary parsers for Android AXML manifests and ELF shared libraries."""

import struct

RES_XML_TYPE = 0x0003
RES_STRING_POOL_TYPE = 0x0001
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_RESOURCE_MAP_TYPE = 0x0180

ATTR_VERSION_CODE = 0x0101021B
ATTR_EXTRACT_NATIVE_LIBS = 0x010104EA
ATTR_VERSION_CODE_MAJOR = 0x01010576
ATTR_IS_SPLIT_REQUIRED = 0x01010591

TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

ELF_MAGIC = b"\x7fELF"
ELF_PAGE_16K = 16384
PT_LOAD = 1
ARCH_64_ABIS = frozenset({"arm64-v8a", "x86_64", "riscv64"})
MAX_ELF_HEADER_BYTES = 65536
MAX_ELF_PHDRS = 256


def decode_axml_string_pool(data, start, header_size, size):
    """Decode strings from an Android binary XML string pool chunk."""
    if size < 28 or header_size > size or start + size > len(data):
        return []
    string_count, _, flags, strings_start, _ = struct.unpack_from("<5I", data, start + 8)
    is_utf8 = bool(flags & 0x100)
    offsets_pos = start + header_size
    pool_base = start + strings_start
    end_limit = start + size
    if string_count > (size // 4) or offsets_pos + 4 * string_count > end_limit or pool_base > end_limit:
        return []
    out = []
    for index in range(string_count):
        rel = struct.unpack_from("<I", data, offsets_pos + 4 * index)[0]
        pos = pool_base + rel
        if pos >= end_limit:
            out.append("")
            continue
        if is_utf8:
            val = data[pos]
            pos += 2 if (val & 0x80 and pos + 1 < end_limit) else 1
            if pos >= end_limit:
                out.append("")
                continue
            byte_len = data[pos]
            if byte_len & 0x80 and pos + 1 < end_limit:
                byte_len = ((byte_len & 0x7F) << 8) | data[pos + 1]
                pos += 2
            else:
                pos += 1
            out.append(data[pos:min(pos + byte_len, end_limit)].decode("utf-8", errors="replace"))
        else:
            if pos + 2 > end_limit:
                out.append("")
                continue
            u16_len = struct.unpack_from("<H", data, pos)[0]
            if u16_len & 0x8000 and pos + 4 <= end_limit:
                low = struct.unpack_from("<H", data, pos + 2)[0]
                u16_len = ((u16_len & 0x7FFF) << 16) | low
                pos += 4
            else:
                pos += 2
            raw = data[pos:min(pos + u16_len * 2, end_limit)]
            out.append(raw.decode("utf-16-le", errors="replace"))
    return out


def _axml_str(pool, index):
    return pool[index] if 0 <= index < len(pool) else ""


def _axml_bool(pool, dtype, val):
    if dtype in (TYPE_INT_BOOLEAN, TYPE_INT_DEC, TYPE_INT_HEX):
        return bool(val != 0)
    if dtype == TYPE_STRING:
        text = _axml_str(pool, val).strip().lower()
        if text in ("true", "false"):
            return text == "true"
    return None


def _axml_int(pool, dtype, val):
    if dtype in (TYPE_INT_DEC, TYPE_INT_HEX):
        return int(val)
    if dtype == TYPE_STRING:
        text = _axml_str(pool, val).strip()
        try:
            return int(text, 0)
        except ValueError:
            return None
    return None


def read_axml_manifest(data):
    """Extract key manifest attributes from compiled Android binary XML without ``aapt2``."""
    info = {
        "valid": False,
        "package": None,
        "version_code": None,
        "version_code_major": None,
        "split": "",
        "extract_native_libs": None,
        "is_split_required": None,
        "required_split_types": None,
        "has_vending_splits": False,
    }
    if len(data) < 8:
        return info
    root_type, root_hdr, root_size = struct.unpack_from("<HHI", data, 0)
    if root_type != RES_XML_TYPE or root_hdr < 8 or root_size > len(data):
        return info
    info["valid"] = True
    pool = []
    res_ids = []
    cursor = root_hdr
    while cursor + 8 <= root_size:
        ctype, chdr, csize = struct.unpack_from("<HHI", data, cursor)
        if chdr < 8 or csize < chdr or cursor + csize > root_size:
            break
        if ctype == RES_STRING_POOL_TYPE:
            pool = decode_axml_string_pool(data, cursor, chdr, csize)
        elif ctype == RES_XML_RESOURCE_MAP_TYPE:
            count = (csize - chdr) // 4
            res_ids = list(struct.unpack_from(f"<{count}I", data, cursor + chdr))
        elif ctype == RES_XML_START_ELEMENT_TYPE and cursor + chdr + 20 <= cursor + csize:
            _, name_idx, attr_start, attr_size, attr_count = struct.unpack_from("<iiHHH", data, cursor + chdr)
            tag = _axml_str(pool, name_idx)
            if attr_size >= 20:
                attr_pos = cursor + chdr + attr_start
                for index in range(attr_count):
                    entry = attr_pos + index * attr_size
                    if entry + 20 > cursor + csize:
                        break
                    _, a_name, raw_str, _, _, dtype, val = struct.unpack_from("<iiiHBBI", data, entry)
                    rid = res_ids[a_name] if 0 <= a_name < len(res_ids) else None
                    aname = _axml_str(pool, a_name)
                    if tag == "manifest":
                        if aname == "package" and dtype == TYPE_STRING:
                            info["package"] = _axml_str(pool, val) or _axml_str(pool, raw_str) or None
                        elif aname == "split" and dtype == TYPE_STRING:
                            info["split"] = _axml_str(pool, val) or _axml_str(pool, raw_str) or ""
                        elif rid == ATTR_VERSION_CODE or aname == "versionCode":
                            info["version_code"] = _axml_int(pool, dtype, val)
                        elif rid == ATTR_VERSION_CODE_MAJOR or aname == "versionCodeMajor":
                            info["version_code_major"] = _axml_int(pool, dtype, val)
                        elif aname == "requiredSplitTypes" and dtype == TYPE_STRING:
                            info["required_split_types"] = _axml_str(pool, val) or _axml_str(pool, raw_str) or None
                    elif tag == "application":
                        if rid == ATTR_EXTRACT_NATIVE_LIBS or aname == "extractNativeLibs":
                            parsed = _axml_bool(pool, dtype, val)
                            if parsed is not None:
                                info["extract_native_libs"] = parsed
                        elif rid == ATTR_IS_SPLIT_REQUIRED or aname == "isSplitRequired":
                            parsed = _axml_bool(pool, dtype, val)
                            if parsed is not None:
                                info["is_split_required"] = parsed
                    elif tag == "meta-data" and aname == "name" and dtype == TYPE_STRING:
                        mval = _axml_str(pool, val) or _axml_str(pool, raw_str)
                        if mval in ("com.android.vending.splits", "com.android.vending.splits.required"):
                            info["has_vending_splits"] = True
        cursor += csize
    return info


def inspect_elf_alignment(stream):
    """Inspect ELF ``PT_LOAD`` ``p_align`` values from a stream without loading the whole file.

    Returns ``None`` if ``stream`` is not a complete readable ELF header + program header table,
    or ``{"bits": 32|64, "min_align": int, "aligned_16k": bool}``.
    """
    head = stream.read(64)
    if len(head) < 52 or head[:4] != ELF_MAGIC:
        return None
    ei_class = head[4]
    ei_data = head[5]
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        return None
    endian = "<" if ei_data == 1 else ">"
    if ei_class == 1:
        bits = 32
        e_phoff, = struct.unpack_from(endian + "I", head, 28)
        e_phentsize, e_phnum = struct.unpack_from(endian + "HH", head, 42)
        min_ent = 32
    else:
        if len(head) < 64:
            return None
        bits = 64
        e_phoff, = struct.unpack_from(endian + "Q", head, 32)
        e_phentsize, e_phnum = struct.unpack_from(endian + "HH", head, 54)
        min_ent = 56
    if e_phnum == 0 or e_phnum > MAX_ELF_PHDRS or e_phentsize < min_ent:
        return None
    ph_end = e_phoff + e_phnum * e_phentsize
    if ph_end > MAX_ELF_HEADER_BYTES:
        return None
    rest = stream.read(ph_end - len(head)) if ph_end > len(head) else b""
    buf = head + rest
    if len(buf) < ph_end:
        return None
    aligns = []
    for idx in range(e_phnum):
        off = e_phoff + idx * e_phentsize
        p_type = struct.unpack_from(endian + "I", buf, off)[0]
        if p_type != PT_LOAD:
            continue
        if bits == 32:
            p_align = struct.unpack_from(endian + "I", buf, off + 28)[0]
        else:
            p_align = struct.unpack_from(endian + "Q", buf, off + 48)[0]
        aligns.append(p_align)
    if not aligns:
        return None
    min_align = min(aligns)
    aligned_16k = all(a >= ELF_PAGE_16K and a % ELF_PAGE_16K == 0 for a in aligns)
    return {"bits": bits, "min_align": min_align, "aligned_16k": aligned_16k}
