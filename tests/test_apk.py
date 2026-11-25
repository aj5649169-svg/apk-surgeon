"""CI exercises a real APK round trip using the Android build tools."""
import os
from pathlib import Path
import subprocess

import pytest

from apk_surgeon.scanner import ANDROID, parse_manifest


@pytest.mark.skipif("TEST_ANDROID_JAR" not in os.environ, reason="Android SDK integration fixture")
def test_signed_apk(tmp_path):
    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text(f'''<manifest xmlns:android="{ANDROID[1:-1]}" package="org.example.fixture">
    <uses-sdk android:minSdkVersion="23"/><application android:label="Fixture">
    <receiver android:name="com.google.android.gms.measurement.AppMeasurementReceiver" android:enabled="false"/>
    </application></manifest>'''.replace(' android:enabled="false"', ''))
    src, out = tmp_path/"fixture.apk", tmp_path/"clean.apk"
    def run(*args):
        subprocess.run(list(map(str,args)), check=True)
    run("aapt2", "link", "-I", os.environ["TEST_ANDROID_JAR"], "--manifest", manifest, "-o", src)
    run("apk-surgeon", "scan", src)
    run("apk-surgeon", "clean", src, "--yes", "-o", out)
    run("apksigner", "verify", out)
    decoded = tmp_path/"check"
    run("apktool", "d", out, "-o", decoded)
    assert parse_manifest(decoded/"AndroidManifest.xml").xpath("//receiver")[0].get(ANDROID+"enabled") == "false"
    assert (tmp_path/"privacy-report.md").is_file()
