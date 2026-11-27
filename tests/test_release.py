import json
import os
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from apk_surgeon.bundles import select_abi
from apk_surgeon.evidence import assess, endpoints
from apk_surgeon.scanner import ANDROID, parse_manifest
from apk_surgeon.verify import verify


@pytest.mark.parametrize(("marker", "verdict"), [
    ("", "SAFE"), ("Lcom/google/android/gms/auth/api/signin/GoogleSignIn;", "CAUTION"),
    ("GET_SIGNING_CERTIFICATES", "HIGH RISK"),
    ("Lcom/google/android/play/core/integrity/IntegrityManager;", "HIGH RISK"),
])
def test_static_evidence(tmp_path, marker, verdict):
    source = tmp_path / "smali/a/b/c.smali"
    source.parent.mkdir(parents=True)
    source.write_text('.class public La/b/c;\n    const-string/jumbo v0, "https://api.mixpanel.com/track"\n' + marker)
    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text(f'<manifest xmlns:android="{ANDROID[1:-1]}"><application><meta-data '
                        'android:name="io.branch.sdk.BranchKey" android:value="secret"/></application></manifest>')
    evidence, safety = assess(tmp_path, parse_manifest(manifest))
    assert evidence == {"Mixpanel": ["endpoint: api.mixpanel.com"], "Branch": ["manifest key: io.branch.sdk.BranchKey"]}
    assert safety["verdict"] == verdict
    assert not endpoints('const-string v0, "https://onesignal.com.unrelated.example"')


def test_abi_selection():
    parts = list(map(Path, ["base.apk", "split_config.arm64_v8a.apk", "split_feature.config.armeabi_v7a.apk",
                            "split_config.en.apk", "split_feature.apk"]))
    assert select_abi(parts, None)[0] == parts
    assert select_abi(parts, "arm64-v8a")[0] == parts[:2] + parts[3:]
    with pytest.raises(ValueError, match="unavailable"):
        select_abi(parts, "x86")


def test_bad_alignment_and_mismatched_certificates(tmp_path, monkeypatch):
    parts = [tmp_path / "base.apk", tmp_path / "split.apk"]
    for part in parts:
        with zipfile.ZipFile(part, "w") as archive:
            archive.writestr("x", b"misaligned")
    def signed(command, **kwargs):
        digest = ("a" if command[-1] == str(parts[0]) else "b") * 64
        return subprocess.CompletedProcess(command, 0, f"Signer #1 certificate SHA-256 digest: {digest}", "")
    monkeypatch.setattr(subprocess, "run", signed)
    report = verify(parts)
    assert not report["ok"] and not report["apks"][0]["aligned"]
    assert "Signing certificates differ from base.apk" in report["apks"][1]["errors"]


@pytest.mark.skipif("TEST_ANDROID_JAR" not in os.environ, reason="Android SDK integration fixture")
def test_resource_bypass_roundtrip(tmp_path, monkeypatch):
    import re
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    def run(*args):
        argv = [str(arg) for arg in args]
        argv[0] = shutil.which(argv[0]) or argv[0]
        return subprocess.check_output(argv, text=True)
    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text(f'<manifest xmlns:android="{ANDROID[1:-1]}" package="org.example.fixture">'
                        '<uses-sdk android:minSdkVersion="23"/><application android:label="fixture"/></manifest>')
    raw = tmp_path / "res/raw/fixture.txt"
    raw.parent.mkdir(parents=True)
    raw.write_text("opaque resource payload")
    resources = tmp_path / "compiled.zip"
    run("aapt2", "compile", "--dir", raw.parents[1], "-o", resources)
    source = tmp_path / "source.apk"
    run("aapt2", "link", "-I", os.environ["TEST_ANDROID_JAR"], "--manifest", manifest, "-o", source, resources)
    java = tmp_path / "FirebaseCrashlytics.java"
    java.write_text("package com.google.firebase.crashlytics; public class FirebaseCrashlytics {"
                    "public void log(String msg) {System.out.println(msg);} }")
    run("javac", "--release", "8", "-d", tmp_path, java)
    run("d8", "--lib", os.environ["TEST_ANDROID_JAR"], "--output", tmp_path,
        tmp_path / "com/google/firebase/crashlytics/FirebaseCrashlytics.class")
    with zipfile.ZipFile(source, "a") as archive:
        archive.write(tmp_path / "classes.dex", "classes.dex")
    out = tmp_path / "result.apk"
    assert json.loads(run("apk-surgeon", "scan", source, "--json"))["trackers"][0]["hooks"]
    run("apk-surgeon", "clean", source, "--smali-only", "--yes", "-o", out)
    with zipfile.ZipFile(source) as before, zipfile.ZipFile(out) as after:
        for name in before.namelist():
            if name != "classes.dex":
                assert before.read(name) == after.read(name)
        assert before.read("classes.dex") != after.read("classes.dex")
    assert json.loads(run("apk-surgeon", "verify", out, "--json"))["ok"]
    decoded = tmp_path / "verify"
    run("apktool", "d", "-r", out, "-o", decoded)
    smali = next(decoded.rglob("FirebaseCrashlytics.smali")).read_text()
    assert re.search(r'\.method public log\([^\n]+\n\s*\.locals \d+\s+return-void', smali)
