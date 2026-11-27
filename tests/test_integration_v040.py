"""End-to-end v0.4.0 coverage on real Android artifacts.

Needs JDK 17, Build Tools 35 and (for APKEditor paths) APKEditor 1.4.9.  The
suite is skipped unless ``TEST_ANDROID_JAR`` is set, which CI does.
"""

import json
import os
import shutil
import subprocess
import zipfile

import pytest

from apk_surgeon.scanner import ANDROID, parse_manifest

pytestmark = pytest.mark.skipif("TEST_ANDROID_JAR" not in os.environ, reason="Android SDK integration fixture")

TRACKER = "com/google/firebase/analytics/FirebaseAnalytics"
RECEIVER = "com.google.android.gms.measurement.AppMeasurementReceiver"
NEEDS_APKEDITOR = pytest.mark.skipif(
    not os.environ.get("APK_SURGEON_APKEDITOR_JAR"), reason="APKEditor fixture not installed"
)


def run(*args, check=True):
    return subprocess.run([str(arg) for arg in args], check=check, text=True, capture_output=True)


def cli(*args, check=True):
    return run("apk-surgeon", *args, check=check)


def build_apk(tmp_path, *, two_dex=False, split=False):
    """Compile a tiny APK with a tracker class, a second class and res/raw."""
    source = tmp_path / "src"
    manifest = source / "AndroidManifest.xml"
    raw = source / "res/raw/note.txt"
    raw.parent.mkdir(parents=True, exist_ok=True)
    raw.write_text("payload")
    split_attr = ' split="config.en"' if split else ""
    manifest.write_text(
        f'<manifest xmlns:android="{ANDROID[1:-1]}" package="org.example.fixture"{split_attr} '
        'android:versionCode="1"><uses-sdk android:minSdkVersion="23"/>'
        '<application android:label="Fixture">'
        f'<receiver android:name="{RECEIVER}"/><activity android:name=".MainActivity"/>'
        '</application></manifest>'
    )
    java = source / "java" / (TRACKER + ".java")
    java.parent.mkdir(parents=True, exist_ok=True)
    java.write_text(
        "package com.google.firebase.analytics;\n"
        "public class FirebaseAnalytics {\n"
        '  public static final String URL = "https://app-measurement.com/a";\n'
        "  public void logEvent(String name, android.os.Bundle params) { System.out.println(name + URL); }\n"
        "  public void lock(android.view.Window window) { window.addFlags(0x2000); }\n"
        "}\n"
    )
    other = source / "java" / "com/example/Other.java"
    other.parent.mkdir(parents=True, exist_ok=True)
    other.write_text("package com.example;\npublic class Other { public static void keep() {} }\n")
    compiled = tmp_path / "compiled.zip"
    run("aapt2", "compile", "--dir", source / "res", "-o", compiled)
    apk = tmp_path / ("split.apk" if split else "fixture.apk")
    run("aapt2", "link", "-I", os.environ["TEST_ANDROID_JAR"], "--manifest", manifest, "-o", apk, compiled)
    classes = tmp_path / "classes"
    run("javac", "--release", "8", "-d", classes, java, other)
    one = tmp_path / "dex1"
    run("d8", "--lib", os.environ["TEST_ANDROID_JAR"], "--output", one,
        classes / (TRACKER + ".class"))
    dexs = {"classes.dex": (one / "classes.dex").read_bytes()}
    if two_dex:
        second = tmp_path / "dex2"
        run("d8", "--lib", os.environ["TEST_ANDROID_JAR"], "--output", second,
            classes / "com/example/Other.class")
        dexs["classes2.dex"] = (second / "classes.dex").read_bytes()
    with zipfile.ZipFile(apk, "a") as archive:
        for name, data in dexs.items():
            archive.writestr(name, data)
    return apk


def copy_with(apk, dest, members):
    shutil.copy2(apk, dest)
    with zipfile.ZipFile(dest, "a") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return dest


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    return build_apk(tmp_path)


def test_scan_reports_engine_frameworks_sinkhole_and_verdict(tmp_path, fixture):
    apk = copy_with(fixture, tmp_path / "native.apk", {"lib/arm64-v8a/libflutter.so": b"\x7fELF"})
    result = json.loads(cli("scan", apk, "--json").stdout)
    assert result["engine"] == "apktool"
    assert result["detected_frameworks"] == ["Flutter"]
    assert result["safety"]["verdict"] == "SAFE"
    assert "https://app-measurement.com/a" in result["sinkhole"]["candidates"]
    assert result["sinkhole"]["endpoint"] == "https://127.0.0.1/"
    assert any(row["hooks"] for row in result["trackers"])


@NEEDS_APKEDITOR
def test_clean_with_apkeditor_and_sinkhole(tmp_path, fixture):
    out = tmp_path / "out" / "clean.apk"
    cli("clean", fixture, "-o", out, "--engine", "apkeditor", "--sinkhole", "--yes")
    verified = json.loads(cli("verify", out, "--json").stdout)
    assert verified["ok"], verified
    report = (out.parent / "privacy-report.md").read_text()
    assert "Engine: apkeditor" in report
    assert "Sinkholed URLs: 1" in report
    with zipfile.ZipFile(out) as archive:
        assert b"127.0.0.1" in archive.read("classes.dex")
        assert "META-INF/CERT.SF" not in archive.namelist()
    assert (out.parent / "clean.backups").is_dir()


@NEEDS_APKEDITOR
def test_merge_splits_into_standalone_apk(tmp_path, fixture, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    split = build_apk(tmp_path / "build", split=True)
    bundle = tmp_path / "bundle.xapk"
    with zipfile.ZipFile(bundle, "w") as archive:
        archive.write(fixture, "org.example.fixture.apk")
        archive.write(split, "config.en.apk")
        archive.writestr("info.json", "{}")
    out = tmp_path / "merged" / "standalone.apk"
    cli("clean", bundle, "--merge-splits", "--yes", "-o", out)
    assert zipfile.is_zipfile(out)
    assert json.loads(cli("verify", out, "--json").stdout)["ok"]


def test_pairip_is_blocked_and_force_unsafe_overrides(tmp_path, fixture):
    blocked = copy_with(fixture, tmp_path / "pairip.apk", {"lib/arm64-v8a/libpairipcore.so": b"\x7fELF"})
    refused = cli("clean", blocked, "--yes", "-o", tmp_path / "never" / "x.apk", check=False)
    assert refused.returncode != 0
    assert "Pairip" in refused.stderr
    assert not (tmp_path / "never" / "x.apk").exists()
    out = tmp_path / "forced" / "x.apk"
    cli("clean", blocked, "--yes", "--force-unsafe", "-o", out)
    assert json.loads(cli("verify", out, "--json").stdout)["ok"]
    assert "--force-unsafe override used" in (out.parent / "privacy-report.md").read_text()


def test_selective_dex_copies_untouched_dex_bytes(tmp_path, fixture):
    apk = build_apk(tmp_path / "selective", two_dex=True)
    with zipfile.ZipFile(apk) as archive:
        untouched = archive.read("classes2.dex")
    out = tmp_path / "selective-out" / "clean.apk"
    cli("clean", apk, "--selective-dex", "--yes", "-o", out)
    with zipfile.ZipFile(out) as archive:
        assert archive.read("classes2.dex") == untouched
        assert archive.read("classes.dex") != original_member(apk, "classes.dex")
    assert json.loads(cli("verify", out, "--json").stdout)["ok"]


def original_member(apk, name):
    with zipfile.ZipFile(apk) as archive:
        return archive.read(name)


def test_trust_user_ca_screenshots_and_recipe(tmp_path, fixture):
    recipe = tmp_path / "recipe.yml"
    recipe.write_text(
        "version: 1\nmethods:\n  - Lcom/example/Other;->keep()V\ndisable_components: []\n"
        "sinkhole_domains: [api.segment.io]\n"
    )
    out = tmp_path / "audit" / "clean.apk"
    cli("clean", fixture, "-o", out, "--yes", "--trust-user-ca", "--allow-screenshots", "--recipe", recipe)
    assert json.loads(cli("verify", out, "--json").stdout)["ok"]
    report = (out.parent / "privacy-report.md").read_text()
    assert "Opt-in patch: User CA trust" in report
    assert "Opt-in patch: Screenshot allowance" in report
    decoded = tmp_path / "decoded"
    run("apktool", "d", out, "-o", decoded)
    tree = parse_manifest(decoded / "AndroidManifest.xml")
    assert tree.getroot().find("application").get(ANDROID + "networkSecurityConfig") == (
        "@xml/apk_surgeon_network_security_config")
    assert (decoded / "res/xml/apk_surgeon_network_security_config.xml").is_file()
    with zipfile.ZipFile(out) as archive:
        assert archive.namelist()
