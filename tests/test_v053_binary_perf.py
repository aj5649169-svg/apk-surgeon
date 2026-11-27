"""v0.5.3 regression tests: raw ZIP streaming, lazy MUTF-8 DEX scan, AXML fallback, ELF 16K, split cleanup."""

import io
import struct
import zipfile
from types import SimpleNamespace

import pytest

from apk_surgeon import binary, bundles, dex_scanner, engines, repack, selective, signing, toolkit, verify
from apk_surgeon.scanner import ANDROID, parse_manifest


def _build_full_axml(
    *,
    package="org.example.app",
    version_code=1,
    version_code_major=None,
    split="",
    extract_native_libs=None,
    is_split_required=None,
    vending_meta=False,
    utf8=True,
):
    """Build a synthetic compiled Android binary manifest exercising AXML tag/attribute types."""
    res_map_ids = []
    strings = ["android", "manifest", "application", "meta-data"]

    def intern(val):
        if val not in strings:
            strings.append(val)
        return strings.index(val)

    def map_attr(name, rid):
        idx = intern(name)
        while len(res_map_ids) <= idx:
            res_map_ids.append(0)
        res_map_ids[idx] = rid
        return idx

    android_ns = strings.index("android")
    attr_ver = map_attr("versionCode", binary.ATTR_VERSION_CODE)
    attr_ver_maj = map_attr("versionCodeMajor", binary.ATTR_VERSION_CODE_MAJOR)
    attr_enl = map_attr("extractNativeLibs", binary.ATTR_EXTRACT_NATIVE_LIBS)
    attr_split_req = map_attr("isSplitRequired", binary.ATTR_IS_SPLIT_REQUIRED)
    attr_meta_name = map_attr("name", 0x01010003)
    attr_pkg = intern("package")
    attr_split = intern("split")

    manifest_attrs = [(-1, attr_pkg, intern(package), 8, 0, binary.TYPE_STRING, intern(package))]
    if version_code is not None:
        manifest_attrs.append((android_ns, attr_ver, -1, 8, 0, binary.TYPE_INT_DEC, version_code))
    if version_code_major is not None:
        manifest_attrs.append((android_ns, attr_ver_maj, -1, 8, 0, binary.TYPE_INT_DEC, version_code_major))
    if split:
        manifest_attrs.append((-1, attr_split, intern(split), 8, 0, binary.TYPE_STRING, intern(split)))

    app_attrs = []
    if extract_native_libs is not None:
        app_attrs.append((android_ns, attr_enl, -1, 8, 0, binary.TYPE_INT_BOOLEAN, 0xFFFFFFFF if extract_native_libs else 0))
    if is_split_required is not None:
        app_attrs.append((android_ns, attr_split_req, -1, 8, 0, binary.TYPE_INT_BOOLEAN, 0xFFFFFFFF if is_split_required else 0))

    meta_chunks = b""
    if vending_meta:
        vidx = intern("com.android.vending.splits.required")
        mattrs = struct.pack("<iiiHBBI", android_ns, attr_meta_name, vidx, 8, 0, binary.TYPE_STRING, vidx)
        meta_chunks = (
            struct.pack("<HHIIiiiHH", binary.RES_XML_START_ELEMENT_TYPE, 16, 36 + len(mattrs), 3, -1, -1, strings.index("meta-data"), 0x14, 20)
            + struct.pack("<HHHH", 1, 0, 0, 0)
            + mattrs
        )

    def pack_start(tag_name, attrs):
        raw_attrs = b"".join(struct.pack("<iiiHBBI", *a) for a in attrs)
        return (
            struct.pack(
                "<HHIIiiiHH",
                binary.RES_XML_START_ELEMENT_TYPE,
                16,
                36 + len(raw_attrs),
                1,
                -1,
                -1,
                strings.index(tag_name),
                0x14,
                20,
            )
            + struct.pack("<HHHH", len(attrs), 0, 0, 0)
            + raw_attrs
        )

    elem_manifest = pack_start("manifest", manifest_attrs)
    elem_app = pack_start("application", app_attrs)

    pool_data = bytearray()
    offsets = []
    for item in strings:
        offsets.append(len(pool_data))
        if utf8:
            enc = item.encode("utf-8")
            pool_data += bytes([len(item), len(enc)]) + enc + b"\x00"
        else:
            enc = item.encode("utf-16-le")
            pool_data += struct.pack("<H", len(item)) + enc + b"\x00\x00"
    while len(pool_data) % 4:
        pool_data.append(0)
    pool_hdr = 28
    strings_start = pool_hdr + 4 * len(strings)
    pool_size = strings_start + len(pool_data)
    pool_chunk = (
        struct.pack("<HHI", binary.RES_STRING_POOL_TYPE, pool_hdr, pool_size)
        + struct.pack("<5I", len(strings), 0, 0x100 if utf8 else 0, strings_start, 0)
        + b"".join(struct.pack("<I", off) for off in offsets)
        + pool_data
    )
    res_map_chunk = struct.pack(
        f"<HHI{len(res_map_ids)}I",
        binary.RES_XML_RESOURCE_MAP_TYPE,
        8,
        8 + 4 * len(res_map_ids),
        *res_map_ids,
    )
    body = pool_chunk + res_map_chunk + elem_manifest + elem_app + meta_chunks
    return struct.pack("<HHI", binary.RES_XML_TYPE, 8, 8 + len(body)) + body


def _minimal_elf(*, bits=64, aligns=(0x4000, 0x4000)):
    if bits == 32:
        e_phoff = 52
        e_phentsize = 32
        ehdr = bytearray(52)
        ehdr[:16] = b"\x7fELF\x01\x01\x01" + b"\x00" * 9
        struct.pack_into("<I", ehdr, 28, e_phoff)
        struct.pack_into("<HH", ehdr, 42, e_phentsize, len(aligns))
        phdrs = b"".join(
            struct.pack("<8I", binary.PT_LOAD, 0, 0, 0, 0x100, 0x100, 5, align) for align in aligns
        )
        return bytes(ehdr) + phdrs
    e_phoff = 64
    e_phentsize = 56
    ehdr = bytearray(64)
    ehdr[:16] = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    struct.pack_into("<Q", ehdr, 32, e_phoff)
    struct.pack_into("<HH", ehdr, 54, e_phentsize, len(aligns))
    phdrs = b"".join(
        struct.pack("<IIQQQQQQ", binary.PT_LOAD, 5, 0, 0, 0, 0x100, 0x100, align) for align in aligns
    )
    return bytes(ehdr) + phdrs


def _zip(path, entries):
    with zipfile.ZipFile(path, "w") as archive:
        for name, data, ctype in entries:
            info = zipfile.ZipInfo(name)
            info.compress_type = ctype
            archive.writestr(info, data)
    return path


def test_repack_raw_streams_deflated_and_upgrades_required_stored(tmp_path, dex_bytes):
    compressible = b"ABCD1234" * 512
    source = _zip(tmp_path / "src.apk", [
        ("META-INF/CERT.SF", b"stale", zipfile.ZIP_DEFLATED),
        ("stamp-cert-sha256", b"stale", zipfile.ZIP_DEFLATED),
        ("resources.arsc", b"table", zipfile.ZIP_DEFLATED),
        ("lib/arm64-v8a/libx.so", b"\x7fELF", zipfile.ZIP_DEFLATED),
        ("assets/big.bin", compressible, zipfile.ZIP_DEFLATED),
        ("classes.dex", dex_bytes(["first"]), zipfile.ZIP_DEFLATED),
        ("classes2.dex", dex_bytes(["second"]), zipfile.ZIP_DEFLATED),
    ])
    with zipfile.ZipFile(source) as before:
        before_asset = before.getinfo("assets/big.bin")

    dest = tmp_path / "repacked.apk"
    repack.repack(source, dest, replace={"classes.dex": dex_bytes(["patched"])})
    with zipfile.ZipFile(dest) as after:
        assert after.testzip() is None
        names = set(after.namelist())
        assert "META-INF/CERT.SF" not in names and "stamp-cert-sha256" not in names
        assert after.getinfo("resources.arsc").compress_type == zipfile.ZIP_STORED
        assert after.getinfo("lib/arm64-v8a/libx.so").compress_type == zipfile.ZIP_STORED
        after_asset = after.getinfo("assets/big.bin")
        assert after_asset.compress_type == zipfile.ZIP_DEFLATED
        assert after_asset.CRC == before_asset.CRC
        assert after_asset.compress_size == before_asset.compress_size
        assert after.read("assets/big.bin") == compressible
        assert after.read("classes.dex") == dex_bytes(["patched"])

    trimmed = tmp_path / "trimmed.apk"
    selective._trimmed(source, trimmed, "classes.dex")
    with zipfile.ZipFile(trimmed) as tzip:
        assert tzip.testzip() is None
        assert "classes2.dex" not in tzip.namelist()
        assert "classes.dex" in tzip.namelist()
        assert tzip.getinfo("assets/big.bin").compress_size == before_asset.compress_size

    # Source ZIP written via unseekable stream sets data-descriptor bit (0x08); raw repack clears it cleanly.
    class _Unseekable(io.RawIOBase):
        def __init__(self):
            self.buf = bytearray()

        def writable(self):
            return True

        def seekable(self):
            return False

        def write(self, b):
            self.buf.extend(b)
            return len(b)

    stream = _Unseekable()
    with zipfile.ZipFile(stream, "w") as s_zip:
        s_zip.writestr("assets/streamed.txt", compressible, compress_type=zipfile.ZIP_DEFLATED)
    dd_src = tmp_path / "dd.apk"
    dd_src.write_bytes(bytes(stream.buf))
    assert zipfile.ZipFile(dd_src).getinfo("assets/streamed.txt").flag_bits & 0x08

    dd_out = tmp_path / "dd-out.apk"
    repack.repack(dd_src, dd_out)
    with zipfile.ZipFile(dd_out) as dd_check:
        assert dd_check.testzip() is None
        assert not (dd_check.getinfo("assets/streamed.txt").flag_bits & 0x08)
        assert dd_check.read("assets/streamed.txt") == compressible


def test_dex_scanner_lazy_matches_ascii_and_unicode(tmp_path, monkeypatch, dex_bytes):
    apk = _zip(tmp_path / "app.apk", [
        ("classes.dex", dex_bytes(["Lcom/example/Safe;", "cafe-\u00e9"]), zipfile.ZIP_STORED),
        ("classes2.dex", dex_bytes(["Lcom/google/firebase/analytics/FirebaseAnalytics;", "host-\u00fc.example"]), zipfile.ZIP_STORED),
    ])

    decode_calls = 0
    real_decode = dex_scanner.mutf8_decode

    def counted_decode(raw):
        nonlocal decode_calls
        decode_calls += 1
        return real_decode(raw)

    monkeypatch.setattr(dex_scanner, "mutf8_decode", counted_decode)
    assert dex_scanner.find_matches(apk, ["com/google/firebase/analytics"]) == {
        "classes2.dex": ["com/google/firebase/analytics"]
    }
    assert decode_calls == 0

    # Non-ASCII needle still triggers exact MUTF-8 decoding cleanly.
    assert dex_scanner.find_matches(apk, ["host-\u00fc.example"]) == {
        "classes2.dex": ["host-\u00fc.example"]
    }
    assert decode_calls > 0


def test_bundles_unpack_pure_python_axml_fallback_without_aapt2(tmp_path, monkeypatch, dex_bytes):
    base = _zip(tmp_path / "raw-base.apk", [
        ("AndroidManifest.xml", _build_full_axml(package="org.example.bundle", version_code=7, version_code_major=1, utf8=True), zipfile.ZIP_STORED),
        ("classes.dex", dex_bytes(["ok"]), zipfile.ZIP_STORED),
    ])
    split = _zip(tmp_path / "raw-arm64.apk", [
        ("AndroidManifest.xml", _build_full_axml(package="org.example.bundle", version_code=7, version_code_major=1, split="config.arm64_v8a", utf8=False), zipfile.ZIP_STORED),
    ])
    xapk = _zip(tmp_path / "bundle.xapk", [
        ("config.arm64_v8a.apk", split.read_bytes(), zipfile.ZIP_DEFLATED),
        ("org.example.bundle.apk", base.read_bytes(), zipfile.ZIP_DEFLATED),
    ])

    monkeypatch.setattr(engines, "resolve_executable", lambda name: str(tmp_path / "missing-aapt2"))
    work = tmp_path / "unpacked"
    work.mkdir()
    parts = bundles.unpack(xapk, work)
    assert [p.name for p in parts] == ["base.apk", "split_config.arm64_v8a.apk"]

    mismatch_split = _zip(tmp_path / "bad-ver.apk", [
        ("AndroidManifest.xml", _build_full_axml(package="org.example.bundle", version_code=8, split="config.arm64_v8a"), zipfile.ZIP_STORED),
    ])
    bad_xapk = _zip(tmp_path / "bad.xapk", [
        ("base.apk", base.read_bytes(), zipfile.ZIP_DEFLATED),
        ("split.apk", mismatch_split.read_bytes(), zipfile.ZIP_DEFLATED),
    ])
    bad_work = tmp_path / "bad-work"
    bad_work.mkdir()
    with pytest.raises(ValueError, match="one package/version"):
        bundles.unpack(bad_xapk, bad_work)


def test_elf_pt_load_alignment_inspect_and_verify(tmp_path, monkeypatch, dex_bytes):
    apk_16k = _zip(tmp_path / "ok16.apk", [
        ("classes.dex", dex_bytes(["ok"]), zipfile.ZIP_STORED),
        ("lib/arm64-v8a/libgood.so", _minimal_elf(bits=64, aligns=(0x4000, 0x4000)), zipfile.ZIP_STORED),
    ])
    apk_mixed = _zip(tmp_path / "mixed4k.apk", [
        ("classes.dex", dex_bytes(["ok"]), zipfile.ZIP_STORED),
        ("lib/arm64-v8a/liblegacy.so", _minimal_elf(bits=64, aligns=(0x4000, 0x1000)), zipfile.ZIP_STORED),
        ("lib/armeabi-v7a/lib32.so", _minimal_elf(bits=32, aligns=(0x1000,)), zipfile.ZIP_STORED),
    ])
    bundle = _zip(tmp_path / "splits.xapk", [
        ("base.apk", _zip(tmp_path / "b.apk", [("classes.dex", dex_bytes(["ok"]), zipfile.ZIP_STORED)]).read_bytes(), zipfile.ZIP_STORED),
        ("config.arm64_v8a.apk", apk_mixed.read_bytes(), zipfile.ZIP_STORED),
    ])

    monkeypatch.setattr("apk_surgeon.toolkit.shutil.which", lambda name: None)
    info_ok = toolkit.inspect_apk(apk_16k)
    assert info_ok["native_libs"]["elf_checked"] == 1
    assert info_ok["native_libs"]["elf_16k_aligned"] is True
    assert info_ok["native_libs"]["elf_unaligned"] == []

    info_mixed = toolkit.inspect_apk(apk_mixed)
    assert info_mixed["native_libs"]["elf_checked"] == 2
    assert info_mixed["native_libs"]["elf_16k_aligned"] is False
    assert info_mixed["native_libs"]["elf_unaligned"] == ["lib/arm64-v8a/liblegacy.so"]

    info_bundle = toolkit.inspect_apk(bundle)
    assert info_bundle["native_libs"]["elf_checked"] == 2
    assert info_bundle["native_libs"]["elf_16k_aligned"] is False
    assert info_bundle["native_libs"]["elf_unaligned"] == ["lib/arm64-v8a/liblegacy.so"]

    monkeypatch.setattr(
        verify.subprocess,
        "run",
        lambda cmd, **kw: SimpleNamespace(
            returncode=0, stdout="Signer #1 certificate SHA-256 digest: " + ("ab" * 32) + "\n", stderr=""
        ),
    )
    monkeypatch.setattr(verify, "check_layout", lambda part: None)
    ver = verify.verify([apk_mixed])
    assert ver["ok"] is True
    assert len(ver["warnings"]) == 1
    assert "lib/arm64-v8a/liblegacy.so" in ver["warnings"][0]


def test_normalize_merged_cleans_is_split_required_and_vending_metadata(tmp_path, monkeypatch, dex_bytes):
    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text(
        f'<manifest xmlns:android="{ANDROID[1:-1]}" package="org.example" android:requiredSplitTypes="base__abi">'
        '<application android:isSplitRequired="true" android:extractNativeLibs="false">'
        '<meta-data android:name="com.android.vending.splits.required" android:value="true"/>'
        '<meta-data android:name="com.android.vending.splits" android:resource="@xml/splits0"/>'
        '<meta-data android:name="com.example.keep" android:value="1"/>'
        "</application></manifest>",
        encoding="utf-8",
    )
    changed = toolkit.normalize_manifest_extract_native_libs(
        manifest, has_native_libs=False, stored_and_aligned_16k=False, clean_splits=True
    )
    assert changed is True
    root = parse_manifest(manifest).getroot()
    assert ANDROID + "requiredSplitTypes" not in root.attrib
    app = root.find("application")
    assert ANDROID + "isSplitRequired" not in app.attrib
    meta_names = [m.get(ANDROID + "name") for m in app.findall("meta-data")]
    assert meta_names == ["com.example.keep"]

    axml = _build_full_axml(package="org.example", extract_native_libs=False, is_split_required=True, vending_meta=True)
    info = binary.read_axml_manifest(axml)
    assert info["extract_native_libs"] is False
    assert info["is_split_required"] is True
    assert info["has_vending_splits"] is True

    merged = _zip(tmp_path / "merged.apk", [
        ("classes.dex", dex_bytes(["a"]), zipfile.ZIP_STORED),
        ("AndroidManifest.xml", axml, zipfile.ZIP_STORED),
    ])
    decoded_dir = tmp_path / "decoded"
    decoded_dir.mkdir()
    (decoded_dir / "AndroidManifest.xml").write_text(
        f'<manifest xmlns:android="{ANDROID[1:-1]}" package="org.example">'
        '<application android:isSplitRequired="true">'
        '<meta-data android:name="com.android.vending.splits.required" android:value="true"/>'
        "</application></manifest>",
        encoding="utf-8",
    )
    monkeypatch.setattr(repack, "verify_storage", lambda p: True)
    monkeypatch.setattr(signing, "align", lambda s, d: repack.repack(s, d))
    monkeypatch.setattr(signing, "check_layout", lambda p: None)
    monkeypatch.setattr(engines, "decode_apkeditor", lambda jar, src, out, types=("xml",): engines.DecodeResult("apkeditor", decoded_dir, "xml"))

    def fake_rebuild(jar, root_dir, out_apk):
        _zip(out_apk, [("AndroidManifest.xml", _build_full_axml(package="org.example", is_split_required=None), zipfile.ZIP_STORED)])
        return out_apk

    monkeypatch.setattr(engines, "rebuild_apkeditor", fake_rebuild)
    notes = []
    out = toolkit.normalize_merged_extract_native_libs(
        merged, tmp_path / "work", apkeditor=tmp_path / "APKEditor.jar", notes=notes
    )
    assert out != merged
    assert any("isSplitRequired" in n for n in notes)
