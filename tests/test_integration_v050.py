"""End-to-end v0.5.0 integration tests on real Android build artifacts."""

import json
import os
import shutil
import subprocess
import sys
import zipfile

import pytest

from apk_surgeon.scanner import ANDROID, parse_manifest

pytestmark = pytest.mark.skipif("TEST_ANDROID_JAR" not in os.environ, reason="Android SDK integration fixture")

NEEDS_APKEDITOR = pytest.mark.skipif(
    not os.environ.get("APK_SURGEON_APKEDITOR_JAR"), reason="APKEditor fixture not installed"
)


def run(*args, check=True):
    result = subprocess.run([str(arg) for arg in args], text=True, capture_output=True)
    if check and result.returncode:
        sys.stderr.write(result.stdout + "\n" + result.stderr)
        result.check_returncode()
    return result


def cli(*args, check=True):
    return run("apk-surgeon", *args, check=check)


def _build_fixture_apk(tmp_path, *, split=False, extract_native_libs=None, extra_members=None):
    source = tmp_path / "src"
    manifest = source / "AndroidManifest.xml"
    raw = source / "res/raw/note.txt"
    raw.parent.mkdir(parents=True, exist_ok=True)
    raw.write_text("payload")
    split_attr = f' split="{split}"' if split else ""
    enl_attr = f' android:extractNativeLibs="{extract_native_libs}"' if extract_native_libs is not None else ""
    manifest.write_text(
        f'<manifest xmlns:android="{ANDROID[1:-1]}" package="org.example.toolkit"{split_attr} '
        'android:versionCode="1"><uses-sdk android:minSdkVersion="24"/>'
        f'<application android:label="ToolkitFixture"{enl_attr}>'
        '<activity android:name=".MainActivity"/>'
        '</application></manifest>'
    )
    java = source / "java/com/example/Metrics.java"
    java.parent.mkdir(parents=True, exist_ok=True)
    java.write_text(
        "package com.example;\n"
        "public class Metrics {\n"
        '  public static final String CUSTOM = "https://metrics.custom-example.org/collect";\n'
        "  public static void send() { System.out.println(CUSTOM); }\n"
        "}\n"
    )
    compiled = tmp_path / "compiled.zip"
    run("aapt2", "compile", "--dir", source / "res", "-o", compiled)
    apk = tmp_path / (f"{split}.apk" if split else "base.apk")
    run("aapt2", "link", "-I", os.environ["TEST_ANDROID_JAR"], "--manifest", manifest, "-o", apk, compiled)
    classes = tmp_path / "classes"
    classes.mkdir(parents=True, exist_ok=True)
    run("javac", "--release", "8", "-classpath", os.environ["TEST_ANDROID_JAR"], "-d", classes, java)
    dex_dir = tmp_path / "dex"
    dex_dir.mkdir(parents=True, exist_ok=True)
    run("d8", "--lib", os.environ["TEST_ANDROID_JAR"], "--output", dex_dir, classes / "com/example/Metrics.class")
    with zipfile.ZipFile(apk, "a") as archive:
        if not split:
            archive.write(dex_dir / "classes.dex", "classes.dex")
        for member_name, payload in (extra_members or {}).items():
            archive.writestr(member_name, payload)
    return apk


@pytest.fixture
def base_apk(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    return _build_fixture_apk(tmp_path / "base", extra_members={"lib/arm64-v8a/libdemo.so": b"\x7fELF" + b"\x00" * 60})


def test_inspect_json_on_real_apk(base_apk):
    info = json.loads(cli("inspect", base_apk, "--json").stdout)
    assert info["ok"]
    assert info["archive_type"] == "apk"
    assert info["abis"] == ["arm64-v8a"]
    assert info["resources_arsc"]["stored"] is True
    assert info["dex_files"][0]["name"] == "classes.dex"
    assert info["dex_files"][0]["version"] >= 35
    assert info["badging"]["package"] == "org.example.toolkit"
    assert info["badging"]["application_label"] == "ToolkitFixture"


def test_decode_edit_build_verify_roundtrip(tmp_path, base_apk):
    decoded = tmp_path / "decoded"
    dec_res = json.loads(cli("decode", base_apk, "-o", decoded, "--json").stdout)
    assert dec_res["ok"] and dec_res["engine"] == "apktool"

    # Mutate AndroidManifest label to prove edit round-trips through build
    manifest = decoded / "AndroidManifest.xml"
    manifest.write_text(manifest.read_text().replace("ToolkitFixture", "EditedToolkit"), encoding="utf-8")

    unsigned = tmp_path / "unsigned.apk"
    unsigned_res = json.loads(cli("build", decoded, "-o", unsigned, "--unsigned", "--json").stdout)
    assert unsigned_res["ok"] and not unsigned_res["signed"] and unsigned_res["aligned"]

    built = tmp_path / "built.apk"
    built_res = json.loads(cli("build", decoded, "-o", built, "--json").stdout)
    assert built_res["ok"] and built_res["signed"]
    assert json.loads(cli("verify", built, "--json").stdout)["ok"]

    inspected = json.loads(cli("inspect", built, "--json").stdout)
    assert inspected["badging"]["application_label"] == "EditedToolkit"


def test_sign_strips_stale_metadata_and_verifies(tmp_path, base_apk):
    dirty = tmp_path / "dirty.apk"
    shutil.copy2(base_apk, dirty)
    with zipfile.ZipFile(dirty, "a") as archive:
        archive.writestr("META-INF/CERT.SF", b"stale")
        archive.writestr("stamp-cert-sha256", b"stale")
    before_bytes = dirty.read_bytes()

    signed = tmp_path / "signed.apk"
    res = json.loads(cli("sign", dirty, "-o", signed, "--json").stdout)
    assert res["ok"] and res["signed"] and res["aligned"]
    assert dirty.read_bytes() == before_bytes
    assert json.loads(cli("verify", signed, "--json").stdout)["ok"]
    with zipfile.ZipFile(signed) as archive:
        assert "META-INF/CERT.SF" not in archive.namelist()
        assert "stamp-cert-sha256" not in archive.namelist()


@NEEDS_APKEDITOR
def test_merge_normalizes_extract_native_libs_and_warns_multi_abi(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    base = _build_fixture_apk(tmp_path / "base", extract_native_libs="true")
    arm64 = _build_fixture_apk(
        tmp_path / "arm64", split="config.arm64_v8a",
        extra_members={"lib/arm64-v8a/libdemo.so": b"\x7fELF" + b"\x00" * 60},
    )
    x86 = _build_fixture_apk(
        tmp_path / "x86", split="config.x86_64",
        extra_members={"lib/x86_64/libdemo.so": b"\x7fELF" + b"\x00" * 60},
    )
    bundle = tmp_path / "multi.xapk"
    with zipfile.ZipFile(bundle, "w") as archive:
        archive.write(base, "org.example.toolkit.apk")
        archive.write(arm64, "config.arm64_v8a.apk")
        archive.write(x86, "config.x86_64.apk")

    merged_all = tmp_path / "merged-all.apk"
    res_all = json.loads(cli("merge", bundle, "-o", merged_all, "--json").stdout)
    assert res_all["ok"]
    assert res_all["abis"] == ["arm64-v8a", "x86_64"]
    assert any("Multiple ABIs" in w for w in res_all["warnings"])
    assert json.loads(cli("verify", merged_all, "--json").stdout)["ok"]

    decoded = tmp_path / "dec-merged"
    run("apktool", "d", merged_all, "-o", decoded)
    assert parse_manifest(decoded / "AndroidManifest.xml").getroot().find("application").get(
        ANDROID + "extractNativeLibs"
    ) == "false"

    merged_one = tmp_path / "merged-arm64.apk"
    res_one = json.loads(cli("merge", bundle, "-o", merged_one, "--abi", "arm64-v8a", "--json").stdout)
    assert res_one["ok"]
    assert res_one["abis"] == ["arm64-v8a"]
    assert not res_one["warnings"]


def test_clean_allow_custom_domains_end_to_end(tmp_path, base_apk):
    recipe_path = tmp_path / "recipe.yml"
    recipe_path.write_text("version: 1\nsinkhole_domains: [metrics.custom-example.org]\n")

    denied = cli("clean", base_apk, "--recipe", recipe_path, "--sinkhole", "--yes", "-o", tmp_path / "never.apk", check=False)
    assert denied.returncode != 0
    assert "pure-telemetry allowlist" in denied.stderr

    out = tmp_path / "out/clean.apk"
    result = cli("clean", base_apk, "--recipe", recipe_path, "--sinkhole", "--allow-custom-domains", "--yes", "-o", out)
    assert "--allow-custom-domains" in result.stdout
    assert json.loads(cli("verify", out, "--json").stdout)["ok"]
    assert b"https://127.0.0.1/" in zipfile.ZipFile(out).read("classes.dex")
    assert "--allow-custom-domains" in (out.parent / "privacy-report.md").read_text()
