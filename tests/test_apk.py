"""CI exercises a real APK round trip using the Android build tools."""
import json
import os
import shutil
import subprocess

import pytest

from apk_surgeon.scanner import ANDROID, parse_manifest


def _resolve_cmd(args):
    argv = [str(arg) for arg in args]
    argv[0] = shutil.which(argv[0]) or argv[0]
    return argv


@pytest.mark.skipif("TEST_ANDROID_JAR" not in os.environ, reason="Android SDK integration fixture")
@pytest.mark.parametrize("bundle", [False, "all", "filtered"])
def test_signed_apk(tmp_path, bundle, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text(f'''<manifest xmlns:android="{ANDROID[1:-1]}" package="org.example.fixture" android:versionCode="1">
    <uses-sdk android:minSdkVersion="23"/><application android:label="Fixture">
    <receiver android:name="com.google.android.gms.measurement.AppMeasurementReceiver" android:enabled="false"/>
    </application></manifest>'''.replace(' android:enabled="false"', ''))
    src, out = tmp_path/"fixture.apk", tmp_path/"clean.apk"
    def run(*args):
        subprocess.run(_resolve_cmd(args), check=True)
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
            archive.writestr("info.json", "{}")
            for abi in ("arm64_v8a", "armeabi_v7a"):
                data = manifest.read_text().replace("config.en", "config."+abi)
                other_manifest = tmp_path/"variant"/"AndroidManifest.xml"
                other_manifest.parent.mkdir(exist_ok=True)
                other_manifest.write_text(data)
                other = tmp_path/(abi+".apk")
                run("aapt2","link","-I",os.environ["TEST_ANDROID_JAR"],"--manifest",other_manifest,"-o",other)
                archive.write(other,other.name)
        src, out = package, tmp_path/"clean.apks"
    run("apk-surgeon", "scan", src)
    extra = ["--abi", "arm64-v8a"] if bundle == "filtered" else []
    run("apk-surgeon", "clean", src, "--yes", "-o", out, *extra)
    verified = json.loads(subprocess.check_output(_resolve_cmd(["apk-surgeon", "verify", str(out), "--json"])))
    assert verified["ok"]
    if bundle:
        with zipfile.ZipFile(out) as archive:
            archive.extractall(tmp_path/"install")
        certs = []
        for part in sorted((tmp_path/"install").glob("*.apk")):
            details = subprocess.check_output(
                _resolve_cmd(["apksigner", "verify", "--print-certs", str(part)]), text=True
            )
            certs.append(next(line for line in details.splitlines() if "certificate SHA-256 digest" in line))
        assert len(certs) == (3 if bundle == "filtered" else 4) and len(set(certs)) == 1
        out = tmp_path/"install/base.apk"
    run("apksigner", "verify", out)
    decoded = tmp_path/"check"
    run("apktool", "d", out, "-o", decoded)
    assert parse_manifest(decoded/"AndroidManifest.xml").xpath("//receiver")[0].get(ANDROID+"enabled") == "false"
    assert (tmp_path/"privacy-report.md").is_file()
