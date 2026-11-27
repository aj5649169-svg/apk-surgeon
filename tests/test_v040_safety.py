import zipfile

import pytest

from apk_surgeon import frameworks, repack, sinkhole
from apk_surgeon.evidence import assess

SMALI = '''.class public Lcom/example/Telemetry;
.method public static send()V
    .locals 1
    const-string v0, "https://app-measurement.com/a"
    const-string/jumbo v1, "https://googleads.g.doubleclick.net/pagead"
    invoke-static {v0, v1}, Lcom/example/Sink;->post(Ljava/lang/String;Ljava/lang/String;)V
    return-void
.end method
'''


def test_rewrite_allowlisted_urls_preserves_registers_and_opcodes():
    edited, found = sinkhole.rewrite(SMALI)
    assert "const-string v0, \"https://127.0.0.1/\"" in edited
    assert "const-string/jumbo v1, \"https://127.0.0.1/\"" in edited
    assert len(found) == 2
    assert "Lcom/example/Sink;->post" in edited


def test_denylisted_domains_are_never_rewritten():
    for host in ("https://www.googleapis.com/upload", "https://firebaseio.com/x",
                 "https://graph.facebook.com/me", "https://lh3.googleusercontent.com/a",
                 "https://www.gstatic.com/x", "https://d1.cloudfront.net/app.js",
                 "https://identitytoolkit.googleapis.com/v1", "https://play.googleapis.com/x"):
        text = f'const-string v0, "{host}"'
        assert sinkhole.rewrite(text)[0] == text, host


def test_allowlist_and_denylist_helpers():
    assert sinkhole.allowlisted("api.mixpanel.com")
    assert sinkhole.allowlisted("abc123.ingest.sentry.io")
    assert sinkhole.allowlisted("sdk.iad-04.braze.com")
    assert sinkhole.allowlisted("graph.instagram.com", "/logging_client_events")
    assert not sinkhole.allowlisted("graph.instagram.com", "/oauth/authorize")
    assert not sinkhole.allowlisted("example.com")
    assert sinkhole.denied("sub.googleapis.com")
    assert sinkhole.denied("amazonaws.com")
    assert not sinkhole.denied("adservice.google.com")
    assert sinkhole.sinkholeable("https:\\/\\/app.adjust.com\\/session")
    assert not sinkhole.sinkholeable("app.adjust.com/session")


def test_recipe_cannot_add_protected_domains():
    with pytest.raises(sinkhole.DeniedDomain, match="protected shared domains"):
        sinkhole.validate_recipe_domains(["googleapis.com"])
    with pytest.raises(sinkhole.DeniedDomain, match="not on the pure-telemetry allowlist"):
        sinkhole.validate_recipe_domains(["example.com"])
    assert sinkhole.validate_recipe_domains(["api.segment.io"]) == ["api.segment.io"]


def _apk(tmp_path, members, name="app.apk"):
    path = tmp_path / name
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return path


def test_framework_detection(tmp_path):
    apk = _apk(tmp_path, {
        "lib/arm64-v8a/libflutter.so": b"x",
        "lib/arm64-v8a/libil2cpp.so": b"x",
        "lib/x86_64/libhermes.so": b"x",
        "lib/armeabi-v7a/libmonodroid.so": b"x",
    })
    assert frameworks.detect([apk]) == ["Flutter", "React Native", "Unity", "Xamarin/MAUI"]
    assert not frameworks.has_pairip_library([apk])
    assert frameworks.FRAMEWORK_CAVEAT in frameworks.FRAMEWORK_CAVEAT


def test_pairip_from_library_and_dex_strings(tmp_path, dex_bytes):
    lib = _apk(tmp_path, {"lib/arm64-v8a/libpairipcore.so": b"x"})
    assert frameworks.has_pairip_library([lib])
    assert frameworks.pairip_detected([lib])[0]
    dex = _apk(tmp_path, {"classes.dex": dex_bytes(["com.pairip.VMRunner", "Lcom/pairip/LicenseClient;"])})
    blocked, reasons = frameworks.pairip_detected([dex])
    assert blocked
    assert any("VMRunner" in reason for reason in reasons)
    clean = _apk(tmp_path, {"classes.dex": b"junk"}, name="clean.apk")
    assert not frameworks.pairip_detected([clean])[0]


def test_evidence_verdicts(tmp_path):
    root = tmp_path / "decoded"
    root.mkdir()
    source = root / "smali/a.smali"
    source.parent.mkdir()
    source.write_text('.class public La;\n    const-string v0, "https://api.mixpanel.com/track"\n')
    lib = _apk(tmp_path, {"lib/arm64-v8a/libpairipcore.so": b"x"})
    evidence, safety = assess(root, None, apks=[lib])
    assert safety["verdict"] == "BLOCKED (Pairip VM)"
    assert safety["blocked"]
    toml = tmp_path / "toml"
    toml.mkdir()
    (toml / "smali").mkdir()
    (toml / "smali/x.smali").write_text(".class public Lx;\nFirebaseAppCheck PlayIntegrityAppCheckProvider")
    _, safety = assess(toml, None, apks=[])
    assert safety["verdict"] == "HIGH RISK"
    (toml / "smali/x.smali").write_text(".class public Lx;\ncom/google/android/gms/auth/api/signin/")
    _, safety = assess(toml, None, apks=[])
    assert safety["verdict"] == "CAUTION"
    (toml / "smali/x.smali").write_text(".class public Lx;\n")
    evidence, safety = assess(toml, None, apks=[])
    assert safety["verdict"] == "SAFE"
    assert evidence == {}


def test_evidence_reports_framework_caveat(tmp_path):
    root = tmp_path / "decoded"
    (root / "smali").mkdir(parents=True)
    apk = _apk(tmp_path, {"lib/arm64-v8a/libflutter.so": b"x"})
    _, safety = assess(root, None, apks=[apk])
    assert safety["detected_frameworks"] == ["Flutter"]
    assert "Native framework" in safety["caveat"]


@pytest.mark.parametrize(("name", "stale"), [
    ("META-INF/MANIFEST.MF", True),
    ("META-INF/CERT.SF", True),
    ("META-INF/CERT.RSA", True),
    ("META-INF/CERT.DSA", True),
    ("META-INF/CERT.EC", True),
    ("META-INF/BNDLTOOL.SF", True),
    ("META-INF/BNDLTOOL.RSA", True),
    ("stamp-cert-sha256", True),
    ("META-INF/services/com.example.Service", False),
    ("META-INF/com/android/build/gradle/app-metadata.properties", False),
    ("res/raw/keep.txt", False),
])
def test_stale_metadata_detection(name, stale):
    assert repack.is_stale_metadata(name) is stale


def test_repack_strips_metadata_and_preserves_storage(tmp_path, dex_bytes):
    source = tmp_path / "in.apk"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("META-INF/MANIFEST.MF", b"stale")
        archive.writestr("META-INF/CERT.SF", b"stale")
        archive.writestr("stamp-cert-sha256", b"stale")
        archive.writestr(zipfile.ZipInfo("resources.arsc"), b"table", compress_type=zipfile.ZIP_DEFLATED)
        archive.writestr("lib/arm64-v8a/libx.so", b"elf", compress_type=zipfile.ZIP_DEFLATED)
        archive.writestr("classes.dex", dex_bytes(["keep"]), compress_type=zipfile.ZIP_STORED)
        archive.writestr(zipfile.ZipInfo("res/raw/a.txt"), b"payload", compress_type=zipfile.ZIP_DEFLATED)
    dest = tmp_path / "out.apk"
    repack.repack(source, dest, replace={"classes2.dex": dex_bytes(["added"])})
    with zipfile.ZipFile(dest) as archive:
        names = archive.namelist()
        assert "META-INF/MANIFEST.MF" not in names
        assert "META-INF/CERT.SF" not in names
        assert "stamp-cert-sha256" not in names
        info = {item.filename: item for item in archive.infolist()}
        assert info["resources.arsc"].compress_type == zipfile.ZIP_STORED
        assert info["lib/arm64-v8a/libx.so"].compress_type == zipfile.ZIP_STORED
        assert info["res/raw/a.txt"].compress_type == zipfile.ZIP_DEFLATED
        assert archive.read("res/raw/a.txt") == b"payload"
        assert archive.read("classes.dex") == dex_bytes(["keep"])
        assert archive.read("classes2.dex") == dex_bytes(["added"])
    assert repack.verify_storage(dest)
