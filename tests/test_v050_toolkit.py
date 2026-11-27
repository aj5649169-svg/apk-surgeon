"""Unit tests for v0.5.0 raw APK toolkit, extractNativeLibs, and custom domains."""

import json
import struct
import zipfile
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from apk_surgeon import cli, engines, recipe, repack, signing, sinkhole, toolkit
from apk_surgeon.scanner import ANDROID, parse_manifest


def _make_apk(path, entries):
    with zipfile.ZipFile(path, "w") as archive:
        for name, (data, ctype) in entries.items():
            info = zipfile.ZipInfo(name)
            info.compress_type = ctype
            archive.writestr(info, data)
    return path


def _build_axml(attr_value, *, utf8=True):
    """Build a minimal valid Android binary XML with <application android:extractNativeLibs=...>."""
    strings = ["android", "manifest", "application", "extractNativeLibs"]
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
        struct.pack("<HHI", 0x0001, pool_hdr, pool_size)
        + struct.pack("<5I", len(strings), 0, 0x100 if utf8 else 0, strings_start, 0)
        + b"".join(struct.pack("<I", off) for off in offsets)
        + pool_data
    )
    res_map = struct.pack("<HHI4I", 0x0180, 8, 24, 0, 0, 0, 0x010104EA)
    attrs = b""
    attr_count = 0 if attr_value is None else 1
    if attr_value is not None:
        attrs = struct.pack("<iiiHBBI", -1, 3, -1, 8, 0, 0x12, 0xFFFFFFFF if attr_value else 0)
    app_chunk = (
        struct.pack("<HHIIiiiHH", 0x0102, 16, 36 + len(attrs), 1, -1, -1, 2, 0x14, 20)
        + struct.pack("<HHHH", attr_count, 0, 0, 0)
        + attrs
    )
    body = pool_chunk + res_map + app_chunk
    return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


def test_decode_flags_fallback_and_force(tmp_path, monkeypatch, dex_bytes):
    apk = _make_apk(tmp_path / "app.apk", {"classes.dex": (dex_bytes(["a"]), zipfile.ZIP_STORED)})
    calls = []

    def fake_apktool(src, root, *, no_res=False, no_src=False):
        calls.append((src, no_res, no_src))
        assert not any(str(item) == "-api" for item in calls[-1])
        if no_res and no_src:
            raise engines.EngineError("aapt2: invalid resource")
        root.mkdir(parents=True, exist_ok=True)
        (root / "apktool.yml").write_text("version: 3.0.3\n")
        return engines.DecodeResult("apktool", root)

    def fake_apkeditor(jar, src, root, *, types=engines.DECODE_TYPES):
        root.mkdir(parents=True, exist_ok=True)
        (root / "archive-info.json").write_text("{}")
        return engines.DecodeResult("apkeditor", root, "xml")

    monkeypatch.setattr(engines, "decode_apktool", fake_apktool)
    monkeypatch.setattr(engines, "decode_apkeditor", fake_apkeditor)
    monkeypatch.setattr(engines, "resolve_apkeditor", lambda explicit=None: tmp_path / "APKEditor.jar")

    out = tmp_path / "out"
    res = toolkit.decode_apk(apk, out, engine="auto")
    assert res["ok"] and res["engine"] == "apktool"
    assert (out / "apktool.yml").is_file()

    with pytest.raises(ValueError, match="--force"):
        toolkit.decode_apk(apk, out)

    res_fallback = toolkit.decode_apk(apk, out, engine="auto", no_res=True, no_src=True, force=True)
    assert res_fallback["engine"] == "apkeditor"
    assert res_fallback["decode_type"] == "xml"
    assert (out / "archive-info.json").is_file()
    assert any("APKEditor" in note for note in res_fallback["notes"])


def test_build_autodetects_engine_unsigned_and_force(tmp_path, monkeypatch, capsys, dex_bytes):
    apktool_dir = tmp_path / "dec-apktool"
    apktool_dir.mkdir()
    (apktool_dir / "apktool.yml").write_text("version: 3.0.3\n")
    apkeditor_dir = tmp_path / "dec-apkeditor"
    (apkeditor_dir / "smali/classes").mkdir(parents=True)
    assert toolkit.detect_decoded_engine(apktool_dir) == "apktool"
    assert toolkit.detect_decoded_engine(apkeditor_dir) == "apkeditor"

    def fake_rebuild_apktool(root, out_apk):
        _make_apk(out_apk, {
            "classes.dex": (dex_bytes(["ok"]), zipfile.ZIP_DEFLATED),
            "resources.arsc": (b"table", zipfile.ZIP_DEFLATED),
            "META-INF/CERT.SF": (b"stale", zipfile.ZIP_DEFLATED),
        })
        return out_apk

    def fake_align(src, dest):
        import shutil

        shutil.copyfile(src, dest)

    monkeypatch.setattr(engines, "rebuild_apktool", fake_rebuild_apktool)
    monkeypatch.setattr(signing, "align", fake_align)
    monkeypatch.setattr(signing, "check_layout", lambda apk: None)

    out = tmp_path / "built.apk"
    res = toolkit.build_apk(apktool_dir, out, unsigned=True)
    assert res["ok"] and res["engine"] == "apktool" and not res["signed"]
    with zipfile.ZipFile(out) as archive:
        info = {i.filename: i for i in archive.infolist()}
        assert info["resources.arsc"].compress_type == zipfile.ZIP_STORED
        assert "META-INF/CERT.SF" not in info
    with pytest.raises(ValueError, match="--force"):
        toolkit.build_apk(apktool_dir, out, unsigned=True)
    assert cli.main(["build", str(apktool_dir), "-o", str(out), "--unsigned", "--force", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] and payload["engine"] == "apktool" and payload["signed"] is False


def test_sign_refuses_in_place_and_strips_metadata(tmp_path, monkeypatch, dex_bytes):
    apk = _make_apk(tmp_path / "raw.apk", {
        "classes.dex": (dex_bytes(["a"]), zipfile.ZIP_DEFLATED),
        "resources.arsc": (b"res", zipfile.ZIP_DEFLATED),
        "lib/arm64-v8a/libdemo.so": (b"\x7fELF", zipfile.ZIP_DEFLATED),
        "META-INF/CERT.SF": (b"stale", zipfile.ZIP_DEFLATED),
        "stamp-cert-sha256": (b"stale", zipfile.ZIP_DEFLATED),
    })
    with pytest.raises(ValueError, match="in place"):
        toolkit.sign_apk(apk, apk, force=True)

    monkeypatch.setattr(signing, "resolve_identity", lambda **k: (tmp_path / "k.jks", "surgeon", {}))
    monkeypatch.setattr(signing, "align", lambda s, d: repack.repack(s, d))
    monkeypatch.setattr(signing, "check_layout", lambda p: None)

    def fake_run(cmd, **kwargs):
        if cmd[:2] == ["apksigner", "sign"]:
            out_path = cmd[cmd.index("--out") + 1]
            repack.repack(cmd[-1], out_path)
        return SimpleNamespace(returncode=0, stdout="Verified using v2 scheme: true\n", stderr="")

    monkeypatch.setattr(signing.subprocess, "run", fake_run)
    monkeypatch.setattr("apk_surgeon.toolkit.verify.verify", lambda parts: {"ok": True, "apks": [{
        "apk": parts[0].name, "certificates_sha256": ["ab" * 32], "aligned": True, "errors": [], "schemes": {},
    }]})
    out = tmp_path / "signed.apk"
    res = toolkit.sign_apk(apk, out)
    assert res["ok"] and res["signed"]
    with zipfile.ZipFile(out) as archive:
        info = {i.filename: i for i in archive.infolist()}
        assert info["resources.arsc"].compress_type == zipfile.ZIP_STORED
        assert info["lib/arm64-v8a/libdemo.so"].compress_type == zipfile.ZIP_STORED
        assert "META-INF/CERT.SF" not in info
        assert "stamp-cert-sha256" not in info
    assert b"stale" in zipfile.ZipFile(apk).read("META-INF/CERT.SF")


def test_extract_native_libs_normalization_and_axml_reader(tmp_path):
    assert toolkit.read_axml_extract_native_libs(_build_axml(True, utf8=True)) is True
    assert toolkit.read_axml_extract_native_libs(_build_axml(False, utf8=False)) is False
    assert toolkit.read_axml_extract_native_libs(_build_axml(None)) is None

    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text(
        f'<manifest xmlns:android="{ANDROID[1:-1]}" package="org.example">'
        '<application android:extractNativeLibs="true"/></manifest>'
    )
    assert toolkit.normalize_manifest_extract_native_libs(
        manifest, has_native_libs=True, stored_and_aligned_16k=True
    )
    assert parse_manifest(manifest).getroot().find("application").get(ANDROID + "extractNativeLibs") == "false"

    assert toolkit.normalize_manifest_extract_native_libs(
        manifest, has_native_libs=True, stored_and_aligned_16k=False
    )
    assert parse_manifest(manifest).getroot().find("application").get(ANDROID + "extractNativeLibs") == "true"

    assert toolkit.normalize_manifest_extract_native_libs(
        manifest, has_native_libs=False, stored_and_aligned_16k=False
    )
    assert parse_manifest(manifest).getroot().find("application").get(ANDROID + "extractNativeLibs") is None


def test_merge_warns_when_multiple_abis_remain(tmp_path, monkeypatch, dex_bytes):
    bundle = tmp_path / "app.xapk"
    _make_apk(bundle, {"dummy.txt": (b"{}", zipfile.ZIP_STORED)})
    base = tmp_path / "base.apk"
    _make_apk(base, {"classes.dex": (dex_bytes(["a"]), zipfile.ZIP_STORED)})
    monkeypatch.setattr("apk_surgeon.toolkit.bundles.unpack", lambda src, work: [base])
    monkeypatch.setattr("apk_surgeon.toolkit.bundles.select_abi", lambda parts, abi: (parts, ["arm64-v8a", "x86_64"]))
    monkeypatch.setattr(engines, "resolve_apkeditor", lambda explicit=None: tmp_path / "APKEditor.jar")

    def fake_merge(jar, splits_dir, merged_out):
        _make_apk(merged_out, {
            "classes.dex": (dex_bytes(["a"]), zipfile.ZIP_STORED),
            "AndroidManifest.xml": (_build_axml(False), zipfile.ZIP_STORED),
            "lib/arm64-v8a/liba.so": (b"\x7fELF", zipfile.ZIP_STORED),
            "lib/x86_64/liba.so": (b"\x7fELF", zipfile.ZIP_STORED),
        })
        return merged_out

    monkeypatch.setattr(engines, "merge_splits", fake_merge)
    monkeypatch.setattr(signing, "align", lambda s, d: repack.repack(s, d))
    monkeypatch.setattr(signing, "check_layout", lambda p: None)

    out = tmp_path / "merged.apk"
    res = toolkit.merge_bundle(bundle, out, unsigned=True)
    assert res["ok"]
    assert res["abis"] == ["arm64-v8a", "x86_64"]
    assert any("Multiple ABIs" in w for w in res["warnings"])


def test_inspect_apk_and_bundle_readonly(tmp_path, monkeypatch, dex_bytes, dex_container_bytes):
    apk = _make_apk(tmp_path / "app.apk", {
        "classes.dex": (dex_container_bytes([["a"], ["b"]]), zipfile.ZIP_STORED),
        "classes2.dex": (dex_bytes(["Lcom/pairip/VMRunner;"]), zipfile.ZIP_STORED),
        "resources.arsc": (b"res", zipfile.ZIP_DEFLATED),
        "lib/arm64-v8a/libflutter.so": (b"\x7fELF", zipfile.ZIP_STORED),
        "lib/armeabi-v7a/libpairipcore.so": (b"\x7fELF", zipfile.ZIP_STORED),
    })
    monkeypatch.setattr("apk_surgeon.toolkit.shutil.which", lambda name: None)
    info = toolkit.inspect_apk(apk)
    assert info["archive_type"] == "apk"
    assert info["abis"] == ["arm64-v8a", "armeabi-v7a"]
    assert info["detected_frameworks"] == ["Flutter"]
    assert info["pairip"]["blocked"] is True
    assert info["resources_arsc"]["stored"] is False
    assert info["dex_files"][0]["container_sections"] == 2
    assert info["dex_files"][0]["version"] == 41
    assert info["dex_files"][1]["version"] == 35
    assert info["badging"] is None

    bundle = tmp_path / "bundle.xapk"
    with zipfile.ZipFile(bundle, "w") as archive:
        archive.write(apk, "base.apk")
    binfo = toolkit.inspect_apk(bundle)
    assert binfo["archive_type"] == "split-bundle"
    assert binfo["split_apks"] == ["base.apk"]

    monkeypatch.setattr("apk_surgeon.toolkit.shutil.which", lambda name: "/usr/bin/aapt2")
    monkeypatch.setattr(
        "apk_surgeon.toolkit.subprocess.run",
        Mock(return_value=SimpleNamespace(
            returncode=0,
            stdout="package: name='org.example.app' versionCode='7' versionName='1.2'\n"
                   "sdkVersion:'24'\ntargetSdkVersion:'35'\napplication-label:'Demo'\n"
                   "uses-permission: name='android.permission.INTERNET'\n",
        )),
    )
    with_aapt = toolkit.inspect_apk(apk)
    assert with_aapt["badging"]["package"] == "org.example.app"
    assert with_aapt["badging"]["permissions_count"] == 1


def test_allow_custom_domains_enables_custom_sinkhole_with_warning(tmp_path, monkeypatch, capsys, dex_bytes):
    rfile = tmp_path / "custom.yml"
    rfile.write_text("version: 1\nsinkhole_domains: [metrics.custom-example.org]\n")
    with pytest.raises(sinkhole.DeniedDomain):
        recipe.load(rfile)

    loaded = recipe.load(rfile, allow_custom_domains=True)
    assert loaded.custom_sinkhole_domains == ["metrics.custom-example.org"]

    denied_recipe = tmp_path / "denied.yml"
    denied_recipe.write_text("version: 1\nsinkhole_domains: [googleapis.com]\n")
    with pytest.raises(sinkhole.DeniedDomain, match="protected shared domains"):
        recipe.load(denied_recipe, allow_custom_domains=True)

    smali = '    const-string v0, "https://metrics.custom-example.org/events"\n'
    edited, reps = sinkhole.rewrite(smali, extra=loaded.sinkhole_domains)
    assert sinkhole.SINKHOLE in edited and len(reps) == 1

    root = tmp_path / "decoded"
    (root / "smali/com/example").mkdir(parents=True)
    (root / "smali/com/example/App.smali").write_text(
        ".class public Lcom/example/App;\n"
        ".method public ping()V\n    .locals 1\n" + smali + "    return-void\n.end method\n"
    )
    (root / "AndroidManifest.xml").write_text(
        f'<manifest xmlns:android="{ANDROID[1:-1]}" package="org.example"><application/></manifest>'
    )
    apk = _make_apk(tmp_path / "app.apk", {
        "classes.dex": (dex_bytes(["https://metrics.custom-example.org/events"]), zipfile.ZIP_STORED),
    })
    out = tmp_path / "out" / "clean.apk"
    monkeypatch.setattr(cli.engines, "decode_apktool", lambda *a, **k: engines.DecodeResult("apktool", root))
    monkeypatch.setattr(
        cli, "rebuild_with",
        lambda req, act, r, u, **k: _make_apk(u, {"classes.dex": (dex_bytes(["https://127.0.0.1/"]), zipfile.ZIP_STORED)}),
    )
    monkeypatch.setattr(cli, "identity", lambda args: (tmp_path / "k.jks", "s", {}))
    monkeypatch.setattr(cli, "sign", lambda u, w, s, c: repack.repack(u, s))
    monkeypatch.setattr(cli, "verify", lambda parts: {"ok": True})

    rc = cli.main(["clean", str(apk), "-o", str(out), "--recipe", str(rfile), "--sinkhole", "--allow-custom-domains", "--yes"])
    assert rc == 0
    stdout = capsys.readouterr().out
    assert "--allow-custom-domains" in stdout
    report = (out.parent / "privacy-report.md").read_text()
    assert "--allow-custom-domains" in report
    assert "metrics.custom-example.org" in report
    assert "Sinkholed URLs: 1" in report
