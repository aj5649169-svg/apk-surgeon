import struct
import zipfile

import pytest

from apk_surgeon import dex_scanner, layout


def test_header_fields(dex_bytes):
    data = dex_bytes(["hello"])
    header = dex_scanner.parse_header(data)
    assert header.version == 35
    assert header.file_size == len(data)
    assert header.header_size == 112
    assert header.string_ids_size == 1
    assert header.string_ids_off == 112
    assert header.as_dict()["version"] == 35


def test_multiple_dex_versions(dex_bytes):
    for version in range(35, 42):
        header = dex_scanner.parse_header(dex_bytes(["a"], version=version))
        assert header.version == version
        assert header.header_size == (120 if version >= 41 else 112)
    with pytest.raises(dex_scanner.DexError):
        dex_scanner.parse_header(dex_bytes(["a"], version=42))
    with pytest.raises(dex_scanner.DexError):
        dex_scanner.parse_header(dex_bytes(["a"], version=41, header_size=112))


@pytest.mark.parametrize("bad", [
    b"", b"dex\n035\x00", b"not-a-dex" + b"\x00" * 200, b"dex\n099\x00" + b"\x00" * 200,
])
def test_rejects_bad_magic(bad):
    with pytest.raises(dex_scanner.DexError):
        dex_scanner.parse_header(bad)


def test_rejects_truncated_and_overflowing_tables(dex_bytes):
    data = bytearray(dex_bytes(["a", "b"]))
    struct.pack_into("<I", data, 0x38, 1000)
    with pytest.raises(dex_scanner.DexError):
        dex_scanner.parse_header(bytes(data))
    data = bytearray(dex_bytes(["a"]))
    struct.pack_into("<I", data, 0x3C, 4)
    with pytest.raises(dex_scanner.DexError):
        dex_scanner.parse_header(bytes(data))
    data = bytearray(dex_bytes(["a"]))
    struct.pack_into("<I", data, 0x28, 0xDEADBEEF)
    with pytest.raises(dex_scanner.DexError):
        dex_scanner.parse_header(bytes(data))


def test_string_offsets_are_bounds_checked(dex_bytes):
    data = bytearray(dex_bytes(["safe"]))
    struct.pack_into("<I", data, 112, 0xFFFFFF)
    with pytest.raises(dex_scanner.DexError):
        list(dex_scanner.strings(bytes(data)))


def test_unterminated_string_is_rejected(dex_bytes):
    data = bytearray(dex_bytes(["safe"]))
    data[-1] = 0x41
    with pytest.raises(dex_scanner.DexError):
        list(dex_scanner.strings(bytes(data)))


def test_mutf8_handles_nul_surrogates_and_junk():
    assert dex_scanner.mutf8_decode(b"a\xc0\x80b") == "a\x00b"
    emoji = dex_scanner.mutf8_decode(b"\xed\xa0\xbd\xed\xb8\x80")
    assert emoji == "\U0001F600"
    assert dex_scanner.mutf8_decode(b"\xff\xfeok") == "\ufffd\ufffdok"
    assert dex_scanner.mutf8_decode(b"\xed\xa0\xbd") == "\ufffd"
    assert dex_scanner.mutf8_decode(b"\xc3") == "\ufffd"


def test_strings_round_trip_unicode(dex_bytes):
    values = ["plain", "with/slash", "naïve", "emoji \U0001F600", "quote\"inside", "nul\x00byte"]
    data = dex_bytes(values)
    assert list(dex_scanner.strings(data)) == values


def test_dex_entries_are_naturally_sorted(tmp_path):
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("classes10.dex", b"x")
        archive.writestr("classes2.dex", b"x")
        archive.writestr("classes.dex", b"x")
        archive.writestr("assets/classes3.dex", b"x")
    with zipfile.ZipFile(apk) as archive:
        assert dex_scanner.dex_entries(archive) == ["classes.dex", "classes2.dex", "classes10.dex"]


def test_find_matches_limits_to_matching_dex(tmp_path, dex_bytes):
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("classes.dex", dex_bytes(["Lcom/example/Main;", "hello"]))
        archive.writestr("classes2.dex", dex_bytes(["Lcom/google/firebase/analytics/FirebaseAnalytics;",
                                                   "https://app-measurement.com/a"]))
    found = dex_scanner.find_matches(apk, ["com/google/firebase/analytics", "app-measurement.com"])
    assert set(found) == {"classes2.dex"}
    assert "com/google/firebase/analytics" in found["classes2.dex"]
    assert dex_scanner.find_matches(apk, []) == {}


def test_malformed_dex_is_reported_not_raised(tmp_path):
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("classes.dex", b"broken")
    assert dex_scanner.find_matches(apk, ["x"]) == {"classes.dex": ["<malformed>"]}


def test_apktool_layout(tmp_path):
    (tmp_path / "AndroidManifest.xml").write_text("<manifest/>")
    first = tmp_path / "smali/a/B.smali"
    first.parent.mkdir(parents=True)
    first.write_text(".class public La/B;")
    second = tmp_path / "smali_classes2/c/D.smali"
    second.parent.mkdir(parents=True)
    second.write_text(".class public Lc/D;")
    assert layout.manifest(tmp_path) == tmp_path / "AndroidManifest.xml"
    assert layout.dex_number(tmp_path, first) == 1
    assert layout.dex_number(tmp_path, second) == 2
    assert {path.name for path in layout.smali_files(tmp_path)} == {"B.smali", "D.smali"}
    assert {path.name for path in layout.smali_files(tmp_path, {2})} == {"D.smali"}


def test_apkeditor_layout(tmp_path):
    (tmp_path / "AndroidManifest.xml").write_text("<manifest/>")
    first = tmp_path / "smali/classes/a/B.smali"
    first.parent.mkdir(parents=True)
    first.write_text(".class public La/B;")
    second = tmp_path / "smali/classes3/c/D.smali"
    second.parent.mkdir(parents=True)
    second.write_text(".class public Lc/D;")
    assert layout.dex_number(tmp_path, first) == 1
    assert layout.dex_number(tmp_path, second) == 3
    assert len(list(layout.smali_files(tmp_path))) == 2
    assert [path.name for path in layout.smali_files(tmp_path, {3})] == ["D.smali"]


def test_missing_manifest(tmp_path):
    assert layout.manifest(tmp_path) is None
    assert layout.res_dir(tmp_path) is None


def test_dex041_container_iterates_all_logical_sections(tmp_path, dex_container_bytes):
    data = dex_container_bytes([
        ["Lcom/example/First;", "keep-me"],
        ["Lcom/google/firebase/analytics/FirebaseAnalytics;", "https://app-measurement.com/a"],
    ])
    headers = list(dex_scanner.iter_headers(data))
    assert len(headers) == 2
    assert all(h.version == 41 and h.header_size == 120 and h.container_size == len(data) for h in headers)
    assert headers[0].header_offset == 0
    assert headers[1].header_offset == headers[0].file_size
    assert list(dex_scanner.strings(data)) == [
        "Lcom/example/First;",
        "keep-me",
        "Lcom/google/firebase/analytics/FirebaseAnalytics;",
        "https://app-measurement.com/a",
    ]
    apk = tmp_path / "container.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("classes.dex", data)
    matches = dex_scanner.find_matches(apk, ["com/google/firebase/analytics", "app-measurement.com"])
    assert matches == {"classes.dex": ["app-measurement.com", "com/google/firebase/analytics"]}

    broken = bytearray(data)
    struct.pack_into("<I", broken, headers[1].header_offset + 0x74, 999)
    with pytest.raises(dex_scanner.DexError, match="header_offset"):
        list(dex_scanner.iter_headers(bytes(broken)))
