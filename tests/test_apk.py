"""CI exercises a real APK round trip using the Android build tools."""
import os
from pathlib import Path
import subprocess

import pytest

from apk_surgeon.scanner import ANDROID, parse_manifest


@pytest.mark.skipif("TEST_ANDROID_JAR" not in os.environ, reason="Android SDK integration fixture")
@pytest.mark.parametrize("bundle", [False, True])
def test_signed_apk(tmp_path, bundle, monkeypatch):
    monkeypatch.setenv("HOME",str(tmp_path))
    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text(f'''<manifest xmlns:android="{ANDROID[1:-1]}" package="org.example.fixture" android:versionCode="1">
    <uses-sdk android:minSdkVersion="23"/><application android:label="Fixture">
    <receiver android:name="com.google.android.gms.measurement.AppMeasurementReceiver" android:enabled="false"/>
    </application></manifest>'''.replace(' android:enabled="false"', ''))
    src, out = tmp_path/"fixture.apk", tmp_path/"clean.apk"
    def run(*args):
        subprocess.run(list(map(str,args)), check=True)
    run("aapt2", "link", "-I", os.environ["TEST_ANDROID_JAR"], "--manifest", manifest, "-o", src)
    if bundle:
        import zipfile
        manifest.write_text(manifest.read_text().replace('package="org.example.fixture"', 'package="org.example.fixture" split="config.en"'))
        split = tmp_path/"english.apk"
        run("aapt2","link","-I",os.environ["TEST_ANDROID_JAR"],"--manifest",manifest,"-o",split)
        package = tmp_path/"input.xapk"
        with zipfile.ZipFile(package,"w") as archive:
            archive.write(src,"org.example.fixture.apk")
            archive.write(split,"config.en.apk")
        src, out = package, tmp_path/"clean.apks"
    run("apk-surgeon", "scan", src)
    run("apk-surgeon", "clean", src, "--yes", "-o", out)
    if bundle:
        with zipfile.ZipFile(out) as archive:
            archive.extractall(tmp_path/"install")
        certs = []
        for part in sorted((tmp_path/"install").glob("*.apk")):
            details = subprocess.check_output(["apksigner","verify","--print-certs",str(part)],text=True)
            certs.append(next(line for line in details.splitlines() if "certificate SHA-256 digest" in line))
        assert len(certs) == 2 and len(set(certs)) == 1
        out = tmp_path/"install/base.apk"
    run("apksigner", "verify", out)
    decoded = tmp_path/"check"
    run("apktool", "d", out, "-o", decoded)
    assert parse_manifest(decoded/"AndroidManifest.xml").xpath("//receiver")[0].get(ANDROID+"enabled") == "false"
    assert (tmp_path/"privacy-report.md").is_file()
