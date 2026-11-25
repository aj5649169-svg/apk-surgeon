from pathlib import Path

from apk_surgeon.patcher import apply, patch_smali, plan
from apk_surgeon.scanner import ANDROID, RULES, parse_manifest, scan

NAME = "com.google.android.gms.measurement.AppMeasurementReceiver"
MANIFEST = f'''<manifest xmlns:android="{ANDROID[1:-1]}" package="org.example">
    <!-- preserve this comment -->
    <application><receiver android:name="{NAME}"/><service android:name=".OwnService"/>
    <provider android:name="com.google.firebase.analytics.KeepProvider"/></application>
</manifest>'''
SIG = "logEvent(Ljava/lang/String;Landroid/os/Bundle;)V"
SOURCE = f""".class public Lcom/google/firebase/analytics/FirebaseAnalytics;
.super Ljava/lang/Object;
.method public {SIG}
    .locals 1
    const/4 v0, 0x1
    return-void
.end method
"""


def test_multidex_and_exact_patch(tmp_path):
    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text(MANIFEST)
    source = tmp_path / "smali_classes2/com/google/firebase/analytics/FirebaseAnalytics.smali"
    source.parent.mkdir(parents=True)
    source.write_text(SOURCE)
    hits = scan(tmp_path)
    assert set(hits) == {"Google Measurement", "Firebase Analytics"}
    assert len(RULES) == 25
    changes = plan(tmp_path, hits)
    assert ".locals 1\n    return-void\n    const/4" in changes[source]
    backup = tmp_path / "backup"
    apply(tmp_path, changes, backup)
    assert (backup/"AndroidManifest.xml.bak").read_text() == MANIFEST
    tree = parse_manifest(manifest)
    assert tree.xpath("//receiver")[0].get(ANDROID+"enabled") == "false"
    assert tree.xpath("//service|//provider")[0].get(ANDROID+"enabled") is None
    assert "preserve this comment" in manifest.read_text()
    assert not plan(tmp_path, scan(tmp_path))


def test_boolean_and_skip_unsupported():
    src = ".method public tracked()Z\n    .locals 1\n    const/4 v0, 1\n    return v0\n.end method"
    result = patch_smali(src, {"tracked()Z"})
    assert ".locals 1\n    const/4 v0, 0x0\n    return v0" in result
    for s in [src.replace(".locals 1", ".locals 0"), src.replace(".locals", ".registers"),
              src.replace("tracked()Z", "other()Z")]:
        assert patch_smali(s, {"tracked()Z"}) == s
