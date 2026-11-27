"""Shared fixtures: a minimal but valid DEX builder for scanner tests."""

import struct

import pytest


def uleb128(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def mutf8_encode(text):
    out = bytearray()
    units = []
    for char in text:
        code = ord(char)
        if code > 0xFFFF:
            code -= 0x10000
            units.append(0xD800 + (code >> 10))
            units.append(0xDC00 + (code & 0x3FF))
        else:
            units.append(code)
    for unit in units:
        if unit == 0:
            out += b"\xc0\x80"
        elif unit < 0x80:
            out.append(unit)
        elif unit < 0x800:
            out += bytes([0xC0 | (unit >> 6), 0x80 | (unit & 0x3F)])
        else:
            out += bytes([0xE0 | (unit >> 12), 0x80 | ((unit >> 6) & 0x3F), 0x80 | (unit & 0x3F)])
    return bytes(out)


def make_dex(strings, version=35, header_size=None):
    """Build a DEX with a valid 112-byte (or 120-byte for 041) header and string pool."""
    if header_size is None:
        header_size = 120 if version >= 41 else 112
    count = len(strings)
    ids_off = header_size
    data_off = ids_off + 4 * count
    payload = bytearray()
    offsets = []
    for text in strings:
        offsets.append(data_off + len(payload))
        payload += uleb128(len(text)) + mutf8_encode(text) + b"\x00"
    size = data_off + len(payload)
    header = bytearray(header_size)
    header[0:8] = b"dex\n0%02d\x00" % version
    struct.pack_into("<I", header, 0x20, size)
    struct.pack_into("<I", header, 0x24, header_size)
    struct.pack_into("<I", header, 0x28, 0x12345678)
    struct.pack_into("<I", header, 0x38, count)
    struct.pack_into("<I", header, 0x3C, ids_off)
    table = b"".join(struct.pack("<I", offset) for offset in offsets)
    return bytes(header) + table + bytes(payload)


@pytest.fixture
def dex_bytes():
    return make_dex
