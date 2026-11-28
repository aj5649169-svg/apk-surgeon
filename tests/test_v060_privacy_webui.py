"""v0.6.0 regression tests: tracker expansion, sinkhole/evidence parity, AndroidX Startup & WebUI parity."""

import json
import os
import re
import threading
import urllib.error
import urllib.request
import zipfile

import pytest

from apk_surgeon import cli, engines, patcher, scanner, sinkhole, ui
from apk_surgeon.evidence import HOSTS, STARTUP_KEYS, assess, endpoints
from apk_surgeon.patcher import patch_smali, plan
from apk_surgeon.recipe import loads as load_recipe
from apk_surgeon.scanner import ANDROID, RULES, parse_manifest, scan


@pytest.fixture
def live_ui(tmp_path):
    server = ui.create_server(host="127.0.0.1", port=0, workspace=tmp_path / "ui-work")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        yield server, base, server.csrf_token
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _req(url, *, method="GET", body=None, headers=None):
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as err:
        return err.code, dict(err.headers), err.read()


def _make_apk(path, entries):
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return path


def test_trackers_json_integrity_no_prefix_overlaps_and_hooks_patchable(tmp_path):
    assert len(RULES) == 39
    names = [rule["name"] for rule in RULES]
    prefixes = [rule["prefix"] for rule in RULES]
    assert len(names) == len(set(names))
    assert len(prefixes) == len(set(prefixes))

    # No rule prefix may shadow another (prevents double-counting Privacy Score).
    for left in prefixes:
        for right in prefixes:
            if left != right:
                assert not right.startswith(left + "."), f"{right} overlaps {left}"

    for rule in RULES:
        assert rule["coverage"] in {"exact-method", "manifest-only", "detection-only"}
        for hook in rule["hooks"]:
            assert hook.startswith("L") and "->" in hook and hook.endswith((")V", ")Z"))
            sig = hook.split("->", 1)[1]
            if sig.endswith(")V"):
                smali = (
                    f".class public La;\n.method public {sig}\n"
                    "    .locals 1\n    const/4 v0, 0x1\n    return-void\n.end method\n"
                )
                assert "return-void\n    const/4" in patch_smali(smali, {sig})
            else:
                bool_smali = (
                    f".class public La;\n.method public {sig}\n"
                    "    .locals 1\n    const/4 v0, 0x1\n    return v0\n.end method\n"
                )
                assert "const/4 v0, 0x0" in patch_smali(bool_smali, {sig})

    # Verify representative newly added trackers scan and patch properly.
    root = tmp_path / "dec"
    smali_ct = root / "smali/com/clevertap/android/sdk/CleverTapAPI.smali"
    smali_ct.parent.mkdir(parents=True)
    smali_ct.write_text(
        ".class public Lcom/clevertap/android/sdk/CleverTapAPI;\n"
        ".method public pushEvent(Ljava/lang/String;)V\n"
        "    .locals 1\n    const/4 v0, 0x1\n    return-void\n.end method\n"
    )
    smali_sg = root / "smali_classes2/com/singular/sdk/Singular.smali"
    smali_sg.parent.mkdir(parents=True)
    smali_sg.write_text(
        ".class public Lcom/singular/sdk/Singular;\n"
        ".method public static event(Ljava/lang/String;)Z\n"
        "    .locals 1\n    const/4 v0, 0x1\n    return v0\n.end method\n"
    )
    hits = scan(root, manifest=False)
    assert set(hits) == {"CleverTap", "Singular"}
    changes = plan(root, hits, manifest=False)
    assert smali_ct in changes and "return-void\n    const/4" in changes[smali_ct]
    assert smali_sg in changes and "const/4 v0, 0x0" in changes[smali_sg]


def test_evidence_hosts_and_sinkhole_allowlist_alignment_and_denylist_safety():
    # Every SDK host in sinkhole.ALLOWLIST must be observable in evidence.HOSTS.
    for host in sinkhole.ALLOWLIST:
        if host == "analytics.s3.amazonaws.com":
            assert sinkhole.denied(host)
            continue
        assert not sinkhole.denied(host), f"ALLOWLIST host {host} conflicts with DENYLIST"
        assert host in HOSTS, f"ALLOWLIST host {host} missing from evidence.HOSTS"

    # Shared infrastructure stays hard-denied even after alignment.
    for shared in ("googleapis.com", "firebaseio.com", "graph.facebook.com", "googleusercontent.com",
                   "gstatic.com", "cloudfront.net", "amazonaws.com", "apple.com", "play.googleapis.com"):
        assert sinkhole.denied(shared)
        assert not sinkhole.sinkholeable(f"https://{shared}/api")

    # Newly aligned hosts detect via evidence.endpoints() AND sinkhole via sinkhole.rewrite().
    new_urls = [
        ("https://api.clevertap.com/a", "CleverTap", "api.clevertap.com"),
        ("https://api.leanplum.com/api", "Leanplum", "api.leanplum.com"),
        ("https://api.singular.net/api/v1/event", "Singular", "api.singular.net"),
        ("https://heapanalytics.com/h", "Heap", "heapanalytics.com"),
        ("https://api.countly.com/i", "Countly", "api.countly.com"),
        ("https://api.tealiumiq.com/v2", "Tealium", "api.tealiumiq.com"),
        ("https://events.adjust.com/session", "Adjust", "events.adjust.com"),
        ("https://api.amplitude.com/2/httpapi", "Amplitude Classic", "api.amplitude.com"),
        ("https://api.branch.io/v1/open", "Branch", "api.branch.io"),
        ("https://app.posthog.com/capture/", "PostHog", "app.posthog.com"),
        ("https://in.appcenter.ms/logs", "Microsoft App Center Analytics", "in.appcenter.ms"),
    ]
    for url, expected_family, expected_host in new_urls:
        snippet = f'.method public a()V\n    .locals 1\n    const-string v0, "{url}"\n    return-void\n.end method\n'
        assert endpoints(snippet) == {expected_host}
        assert HOSTS[expected_host] == expected_family
        edited, reps = sinkhole.rewrite(snippet)
        assert sinkhole.SINKHOLE in edited and reps == [(url, sinkhole.SINKHOLE)]


def test_androidx_startup_metadata_detection_and_selective_disable(tmp_path):
    assert "io.sentry.android.core.SentryInitProvider" in STARTUP_KEYS
    root = tmp_path / "decoded"
    (root / "smali").mkdir(parents=True)
    manifest = root / "AndroidManifest.xml"
    manifest.write_text(
        f'<manifest xmlns:android="{ANDROID[1:-1]}" package="org.example.startup">'
        "<application>"
        '<meta-data android:name="CLEVERTAP_ACCOUNT_ID" android:value="ct-123"/>'
        '<provider android:name="androidx.startup.InitializationProvider" android:exported="false">'
        '  <meta-data android:name="io.sentry.android.core.SentryInitProvider" android:value="androidx.startup"/>'
        '  <meta-data android:name="com.posthog.android.PostHogInitializer" android:value="@string/androidx_startup"/>'
        '  <meta-data android:name="androidx.work.WorkManagerInitializer" android:value="androidx.startup"/>'
        '  <meta-data android:name=".CustomStartupTracker" android:value="androidx.startup"/>'
        "</provider>"
        "</application>"
        "</manifest>",
        encoding="utf-8",
    )

    recipe = load_recipe("version: 1\ndisable_components: [org.example.startup.CustomStartupTracker]\n")
    tree = parse_manifest(manifest)

    hits = scan(root, recipe=recipe)
    assert "startup: io.sentry.android.core.SentryInitProvider" in hits["Sentry"].components
    assert "startup: com.posthog.android.PostHogInitializer" in hits["PostHog"].components

    evidence, safety = assess(root, tree, recipe=recipe)
    assert safety["verdict"] == "SAFE"
    assert "AndroidX Startup" not in evidence
    assert evidence["CleverTap"] == ["manifest key: CLEVERTAP_ACCOUNT_ID"]
    assert evidence["Sentry"] == ["startup initializer: io.sentry.android.core.SentryInitProvider"]
    assert evidence["PostHog"] == ["startup initializer: com.posthog.android.PostHogInitializer"]

    # Without disable_providers=True, only recipe-explicit startup component is removed.
    changes_recipe_only = plan(root, hits, disable_providers=False, recipe=recipe)
    assert manifest in changes_recipe_only
    assert "CustomStartupTracker" not in changes_recipe_only[manifest]
    assert "SentryInitProvider" in changes_recipe_only[manifest]

    # With disable_providers=True, allowlisted tracker initializers are removed,
    # InitializationProvider itself stays enabled, and WorkManager remains untouched.
    changes = plan(root, hits, disable_providers=True, recipe=recipe)
    patched = changes[manifest]
    assert "io.sentry.android.core.SentryInitProvider" not in patched
    assert "com.posthog.android.PostHogInitializer" not in patched
    assert "org.example.startup.CustomStartupTracker" not in patched and ".CustomStartupTracker" not in patched
    assert "androidx.work.WorkManagerInitializer" in patched
    assert "androidx.startup.InitializationProvider" in patched
    assert 'android:enabled="false"' not in patched

    # Applying twice is idempotent.
    patcher.apply(root, changes, tmp_path / "backup")
    assert not plan(root, scan(root, recipe=recipe), disable_providers=True, recipe=recipe)


def test_exodus_invalid_db_raises_clean_value_error(tmp_path):
    root = tmp_path / "dec"
    (root / "smali").mkdir(parents=True)
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid Exodus tracker DB"):
        scanner.exodus(root, bad_json)

    bad_schema = tmp_path / "missing.json"
    bad_schema.write_text(json.dumps({"not_trackers": {}}), encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid Exodus tracker DB"):
        scanner.exodus(root, bad_schema)


def test_webui_paginated_searchable_files_hex_preview_and_symlink_safety(live_ui, tmp_path, monkeypatch, dex_bytes):
    server, base, token = live_ui
    apk = _make_apk(tmp_path / "app.apk", {"classes.dex": dex_bytes(["a"])})
    dec_root = tmp_path / "decoded-tree"
    (dec_root / "smali/com/example").mkdir(parents=True)
    for idx in range(115):
        (dec_root / f"smali/com/example/File{idx:03d}.smali").write_text(f".class public Lcom/example/File{idx:03d};\n")
    (dec_root / "smali/com/example/TargetTracker.smali").write_text(".class public Lcom/example/TargetTracker;\n")
    (dec_root / "AndroidManifest.xml").write_text('<manifest package="org.example.v060"><application/></manifest>')
    (dec_root / "apktool.yml").write_text("version: 3.0.3\n")
    (dec_root / "lib/arm64-v8a").mkdir(parents=True)
    # Valid-UTF8 header bytes containing NULs (ELF binary) and invalid-UTF8 binary > 4 KiB
    (dec_root / "lib/arm64-v8a/libdemo.so").write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 5000)
    (dec_root / "assets").mkdir()
    (dec_root / "assets/blob.bin").write_bytes(b"\xff\xfe\x00\xab\xcd" * 1000)

    # Create a large UTF-8 file where byte MAX_PREVIEW_BYTES lands mid-rune.
    emoji_chunk = ("A" * (ui.MAX_PREVIEW_BYTES - 2)) + "\U0001F600" + "END"
    (dec_root / "assets/big-utf8.txt").write_text(emoji_chunk, encoding="utf-8")

    # Outside symlink should be ignored/rejected.
    outside = tmp_path / "outside.txt"
    outside.write_text("SECRET_OUTSIDE", encoding="utf-8")
    try:
        os.symlink(outside, dec_root / "escape.txt")
    except OSError:
        pass  # Windows without Developer Mode may disallow symlinks

    monkeypatch.setattr(cli.engines, "decode_apktool", lambda *a, **k: engines.DecodeResult("apktool", dec_root))
    st, _, body = _req(
        f"{base}/api/jobs",
        method="POST",
        body=json.dumps({"type": "decode", "path": str(apk)}).encode("utf-8"),
        headers={"X-APK-Surgeon-Token": token, "Content-Type": "application/json"},
    )
    assert st == 202
    job_id = json.loads(body)["job"]["id"]
    with urllib.request.urlopen(f"{base}/api/jobs/{job_id}/events", timeout=5) as stream:
        stream.read()

    # Also test symlink placed directly inside job["decoded_dir"].
    decoded_dir = server.manager.get_job(job_id)["decoded_dir"]
    try:
        os.symlink(outside, decoded_dir / "direct-escape.txt")
    except OSError:
        pass

    # Page 1: priority files first, total count > 115, pagination metadata present
    st1, _, p1_raw = _req(f"{base}/api/jobs/{job_id}/files?page=1&per_page=50")
    p1 = json.loads(p1_raw)
    assert st1 == 200 and p1["ok"]
    assert p1["files"][0] == "AndroidManifest.xml"
    assert p1["files"][1] == "apktool.yml"
    assert len(p1["files"]) == 50
    assert p1["page"] == 1 and p1["per_page"] == 50
    assert p1["total"] >= 120 and p1["total_pages"] == 3
    assert "escape.txt" not in p1["files"]
    assert "direct-escape.txt" not in p1["files"]

    # Page 3: remainder of files
    st3, _, p3_raw = _req(f"{base}/api/jobs/{job_id}/files?page=3&per_page=50")
    p3 = json.loads(p3_raw)
    assert st3 == 200 and p3["page"] == 3 and len(p3["files"]) == p1["total"] - 100

    # Search filter finds target file AND binary .so
    st_q, _, q_raw = _req(f"{base}/api/jobs/{job_id}/files?q=targettracker")
    q_data = json.loads(q_raw)
    assert st_q == 200 and q_data["total"] == 1
    assert q_data["files"] == ["smali/com/example/TargetTracker.smali"]

    st_so, _, so_raw = _req(f"{base}/api/jobs/{job_id}/files?q=.so")
    assert json.loads(so_raw)["files"] == ["lib/arm64-v8a/libdemo.so"]

    # Bad page query returns 400
    st_bad, _, _ = _req(f"{base}/api/jobs/{job_id}/files?page=notanint")
    assert st_bad == 400

    # Binary ELF with NUL bytes triggers hex mode & size metadata (truncated at 4 KiB)
    st_hex1, _, hex1_raw = _req(f"{base}/api/workspace-file?job_id={job_id}&path=lib/arm64-v8a/libdemo.so")
    hex1 = json.loads(hex1_raw)
    assert st_hex1 == 200 and hex1["mode"] == "hex" and hex1["truncated"] is True
    assert hex1["size"] == 5008
    assert "00000000  7f 45 4c 46" in hex1["content"]
    assert "more bytes" in hex1["content"]

    # Binary invalid-UTF8 blob triggers hex mode
    st_hex2, _, hex2_raw = _req(f"{base}/api/workspace-file?job_id={job_id}&path=assets/blob.bin")
    hex2 = json.loads(hex2_raw)
    assert st_hex2 == 200 and hex2["mode"] == "hex" and "00000000  ff fe 00 ab cd" in hex2["content"]

    # Large UTF-8 file cut mid-emoji stays in text mode without crashing or misclassifying as hex!
    st_utf8, _, utf8_raw = _req(f"{base}/api/workspace-file?job_id={job_id}&path=assets/big-utf8.txt")
    utf8 = json.loads(utf8_raw)
    assert st_utf8 == 200 and utf8["mode"] == "text" and utf8["truncated"] is True

    # Symlink escape (if created) is rejected with 403
    if (decoded_dir / "direct-escape.txt").is_symlink():
        st_esc, _, _ = _req(f"{base}/api/workspace-file?job_id={job_id}&path=direct-escape.txt")
        assert st_esc == 403


def test_webui_privacy_studio_tracker_db_and_custom_keystore_and_xhr_assets(live_ui, tmp_path, monkeypatch, dex_bytes):
    server, base, token = live_ui
    apk = _make_apk(tmp_path / "studio.apk", {"classes.dex": dex_bytes(["https://app-measurement.com/a"])})
    dec_root = tmp_path / "decoded"
    (dec_root / "smali/com/custom").mkdir(parents=True)
    (dec_root / "smali/com/custom/Track.smali").write_text(
        '.class public Lcom/custom/Track;\n.method public ping()V\n    .locals 1\n'
        '    const-string v0, "https://app-measurement.com/a"\n    return-void\n.end method\n',
        encoding="utf-8",
    )
    (dec_root / "AndroidManifest.xml").write_text('<manifest package="org.example.studio"><application/></manifest>')
    db = tmp_path / "exodus.json"
    db.write_text(json.dumps({"trackers": {"1": {"name": "CustomExodusTracker", "code_signature": r"com\.custom\.Track"}}}))
    ks = tmp_path / "custom.jks"
    ks.write_bytes(b"jks-bytes")

    monkeypatch.setattr(cli.engines, "decode_apktool", lambda *a, **k: engines.DecodeResult("apktool", dec_root))

    # 1. clean_preview with tracker_db surfaces exodus matches
    st_p, _, p_body = _req(
        f"{base}/api/jobs",
        method="POST",
        body=json.dumps({
            "type": "clean_preview",
            "path": str(apk),
            "sinkhole": True,
            "tracker_db": str(db),
        }).encode("utf-8"),
        headers={"X-APK-Surgeon-Token": token, "Content-Type": "application/json"},
    )
    assert st_p == 202
    jid_p = json.loads(p_body)["job"]["id"]
    with urllib.request.urlopen(f"{base}/api/jobs/{jid_p}/events", timeout=5) as stream:
        stream.read()
    _, _, fin_p = _req(f"{base}/api/jobs/{jid_p}")
    job_p = json.loads(fin_p)["job"]
    assert job_p["status"] == "done"
    assert job_p["result"]["exodus"] == ["CustomExodusTracker"]

    # 2. clean with custom keystore forwards ks params without leaking password in logs/JSON
    seen_creds = {}

    def fake_identity(args):
        seen_creds["keystore"] = args.keystore
        seen_creds["ks_alias"] = args.ks_alias
        seen_creds["ks_pass"] = args.ks_pass
        return ks, args.ks_alias or "surgeon", {"KS_SECRET": args.ks_pass}

    monkeypatch.setattr(cli, "identity", fake_identity)
    monkeypatch.setattr(
        cli, "rebuild_with",
        lambda req, act, r, u, **k: _make_apk(u, {"classes.dex": dex_bytes(["https://127.0.0.1/"])}),
    )
    monkeypatch.setattr(cli, "sign", lambda u, w, s, c: _make_apk(s, {"classes.dex": dex_bytes(["https://127.0.0.1/"])}))

    secret_pass = "super-secret-pass-060"
    st_c, _, c_body = _req(
        f"{base}/api/jobs",
        method="POST",
        body=json.dumps({
            "type": "clean",
            "path": str(apk),
            "sinkhole": True,
            "tracker_db": str(db),
            "keystore": str(ks),
            "ks_alias": "myalias",
            "ks_pass": secret_pass,
        }).encode("utf-8"),
        headers={"X-APK-Surgeon-Token": token, "Content-Type": "application/json"},
    )
    assert st_c == 202
    jid_c = json.loads(c_body)["job"]["id"]
    with urllib.request.urlopen(f"{base}/api/jobs/{jid_c}/events", timeout=5) as stream:
        sse_raw = stream.read().decode("utf-8")
    _, _, fin_c = _req(f"{base}/api/jobs/{jid_c}")
    job_c = json.loads(fin_c)["job"]
    assert job_c["status"] == "done"
    assert seen_creds == {"keystore": str(ks), "ks_alias": "myalias", "ks_pass": secret_pass}
    assert secret_pass not in sse_raw and secret_pass not in fin_c.decode("utf-8")

    # 3. Missing tracker_db fails cleanly
    st_m, _, m_body = _req(
        f"{base}/api/jobs",
        method="POST",
        body=json.dumps({
            "type": "clean_preview",
            "path": str(apk),
            "tracker_db": str(tmp_path / "does-not-exist.json"),
        }).encode("utf-8"),
        headers={"X-APK-Surgeon-Token": token, "Content-Type": "application/json"},
    )
    assert st_m == 202
    jid_m = json.loads(m_body)["job"]["id"]
    with urllib.request.urlopen(f"{base}/api/jobs/{jid_m}/events", timeout=5) as stream:
        stream.read()
    _, _, fin_m = _req(f"{base}/api/jobs/{jid_m}")
    assert json.loads(fin_m)["job"]["status"] == "error"

    # 4. Verify v0.6.0 HTML/JS/CSS assets without unsafe sinks or leaked passwords
    assets = ui.ASSETS_DIR
    html = (assets / "index.html").read_text(encoding="utf-8")
    js = (assets / "app.js").read_text(encoding="utf-8")
    css = (assets / "app.css").read_text(encoding="utf-8")
    for eid in ("upload-progress-track", "btn-cancel-upload", "decoded-search",
                "btn-decoded-prev", "btn-decoded-next", "decoded-file-size",
                "clean-tracker-db", "clean-keystore", "clean-ks-alias", "clean-ks-pass"):
        assert f'id="{eid}"' in html
    assert 'role="progressbar"' in html
    assert "XMLHttpRequest" in js and "upload.onprogress" in js and "fetchDecodedFiles" in js
    assert "--ks-pass" not in js
    assert ".hex-view" in css and ".upload-progress-fill" in css
    for text in (html, js):
        assert "innerHTML" not in text
        assert "outerHTML" not in text
        assert "insertAdjacentHTML" not in text
        assert "document.write" not in text
        assert not re.search(r"\beval\s*\(", text)
