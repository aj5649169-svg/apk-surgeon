"""v0.5.2 regression tests: layout/CA trust, LLM fenced JSON, timeouts, cancel, and shared pipeline."""

import io
import json
import subprocess
import sys
import threading
import time
import zipfile
from types import SimpleNamespace

import pytest

from apk_surgeon import audit, cli, engines, layout, llm, patcher, pipeline
from apk_surgeon.scanner import ANDROID


def _make_zip(path, entries):
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in entries.items():
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, data)
    return path


def test_apkeditor_trust_user_ca_registers_public_xml_and_avoids_ns0(tmp_path):
    root = tmp_path / "apkeditor-decoded"
    pub = root / "resources/package_1/res/values/public.xml"
    pub.parent.mkdir(parents=True)
    (root / "AndroidManifest.xml").write_text(
        '<manifest package="org.example.app"><application/></manifest>', encoding="utf-8"
    )
    pub.write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<resources id="0x7f">\n'
        '  <public id="0x7f010000" type="drawable" name="icon" />\n'
        '  <public id="0x7f080002" type="xml" name="existing" />\n'
        "</resources>\n",
        encoding="utf-8",
    )

    assert layout.res_dir(root) == (root / "resources/package_1/res")
    changes, pkg = audit.trust_user_ca(root)
    assert pkg == "org.example.app"

    manifest_text = changes[root / "AndroidManifest.xml"]
    assert 'xmlns:android="http://schemas.android.com/apk/res/android"' in manifest_text
    assert 'android:networkSecurityConfig="@xml/apk_surgeon_network_security_config"' in manifest_text
    assert "ns0" not in manifest_text

    cfg_path = root / "resources/package_1/res/xml/apk_surgeon_network_security_config.xml"
    assert '<certificates src="user" />' in changes[cfg_path]
    assert 'id="0x7f080003" type="xml" name="apk_surgeon_network_security_config"' in changes[pub]

    # When public.xml has no existing type="xml", allocate the next unused resource type ID.
    root_fresh = tmp_path / "fresh"
    pub_fresh = root_fresh / "resources/package_1/res/values/public.xml"
    pub_fresh.parent.mkdir(parents=True)
    (root_fresh / "AndroidManifest.xml").write_text(
        f'<manifest xmlns:android="{ANDROID[1:-1]}" package="org.example.fresh"><application/></manifest>',
        encoding="utf-8",
    )
    pub_fresh.write_text(
        '<resources id="0x7f"><public id="0x7f010000" type="attr" name="a" /></resources>',
        encoding="utf-8",
    )
    changes_fresh, _ = audit.trust_user_ca(root_fresh)
    assert 'id="0x7f020000" type="xml" name="apk_surgeon_network_security_config"' in changes_fresh[pub_fresh]


def test_patcher_plan_preserves_android_prefix_without_ns0(tmp_path):
    root = tmp_path / "decoded"
    root.mkdir()
    manifest = root / "AndroidManifest.xml"
    manifest.write_text(
        '<manifest package="org.example.bare"><application>'
        '<receiver xmlns:p="http://schemas.android.com/apk/res/android" '
        'p:name="com.google.android.gms.measurement.AppMeasurementReceiver"/>'
        "</application></manifest>",
        encoding="utf-8",
    )
    from apk_surgeon.recipe import Recipe

    custom_recipe = Recipe(disable_components={"com.google.android.gms.measurement.AppMeasurementReceiver"})
    changes = patcher.plan(root, {}, recipe=custom_recipe)
    assert manifest in changes
    assert 'xmlns:android="http://schemas.android.com/apk/res/android"' in changes[manifest]
    assert "ns0" not in changes[manifest]


def test_llm_candidates_apkeditor_layout_and_fenced_json(tmp_path, monkeypatch):
    root = tmp_path / "decoded"
    smali = root / "smali/classes/com/tracker/Ping.smali"
    smali.parent.mkdir(parents=True)
    smali.write_text(
        ".class public Lcom/tracker/Ping;\n"
        ".method public send()V\n"
        "    .locals 1\n"
        '    const-string v0, "https://metrics.example.org/collect"\n'
        "    return-void\n"
        ".end method\n",
        encoding="utf-8",
    )

    found = llm.candidates(root)
    assert len(found) == 1 and found[0][0] == smali

    payload = {
        "choices": [
            {
                "message": {
                    "content": '```json\n{"method_name":"send()V","reason":"telemetry","risk_level":"low","safe_to_noop":true}\n```'
                }
            }
        ]
    }

    class _FakeResp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    class _FakeOpener:
        def open(self, req, timeout=60):
            return _FakeResp(json.dumps(payload).encode("utf-8"))

    monkeypatch.setattr(llm.urllib.request, "build_opener", lambda *a: _FakeOpener())
    results = list(llm.analyze(root, "http://127.0.0.1:11434/v1", "qwen3:4b"))
    assert len(results) == 1
    assert results[0][0] == smali
    assert results[0][1]["safe_to_noop"] is True


def test_engines_run_timeout_streaming_and_cancellation(monkeypatch):
    def fake_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], kwargs.get("timeout", 5))

    monkeypatch.setattr(engines.subprocess, "run", fake_timeout)
    with pytest.raises(engines.EngineError, match="timed out"):
        engines.run(["apktool", "d", "app.apk"], "Apktool decode")

    monkeypatch.undo()
    seen_lines = []
    seen_pids = []
    cancel_event = threading.Event()

    def on_line(line):
        seen_lines.append(line.strip())
        if "STREAM_READY" in line:
            cancel_event.set()

    def on_pid(pid, active):
        seen_pids.append((pid, active))

    start = time.monotonic()
    with pytest.raises(engines.CancelledError):
        with engines.execution_hooks(on_line=on_line, cancel_event=cancel_event, on_pid=on_pid, timeout=15):
            engines.run(
                [sys.executable, "-u", "-c", "import time; print('STREAM_READY', flush=True); time.sleep(30)"],
                "Streaming test",
            )
    elapsed = time.monotonic() - start
    assert elapsed < 10.0
    assert "STREAM_READY" in seen_lines
    assert any(active for _, active in seen_pids)
    assert any(not active for _, active in seen_pids)


def test_pipeline_run_scan_or_clean_merge_default_output_and_apkeditor_preview(tmp_path, monkeypatch, dex_bytes):
    raw_dex = dex_bytes(["https://app-measurement.com/a"])
    src_apk = _make_zip(tmp_path / "base.apk", {"classes.dex": raw_dex})
    bundle = _make_zip(tmp_path / "app.xapk", {"base.apk": src_apk.read_bytes()})

    decoded = tmp_path / "dec"
    (decoded / "smali/classes/com/example").mkdir(parents=True)
    (decoded / "smali/classes/com/example/T.smali").write_text(
        ".class public Lcom/example/T;\n.method public a()V\n    .locals 1\n"
        '    const-string v0, "https://app-measurement.com/a"\n    return-void\n.end method\n',
        encoding="utf-8",
    )
    (decoded / "AndroidManifest.xml").write_text(
        f'<manifest xmlns:android="{ANDROID[1:-1]}" package="org.example.pipe"><application/></manifest>',
        encoding="utf-8",
    )

    monkeypatch.setattr(engines, "resolve_apkeditor", lambda jar=None: tmp_path / "APKEditor.jar")
    monkeypatch.setattr(engines, "decode_apktool", lambda *a, **k: engines.DecodeResult("apkeditor", decoded))

    preview_dir = tmp_path / "preview"
    preview_dir.mkdir()
    args = SimpleNamespace(
        command="clean_preview",
        engine="auto",
        apkeditor_jar=None,
        smali_only=False,
        abi=None,
        merge_splits=False,
        selective_dex=False,
        sinkhole=True,
        trust_user_ca=False,
        allow_screenshots=False,
        strip_ad_permissions=False,
        disable_providers=False,
        allow_custom_domains=False,
        force_unsafe=False,
        keystore=None,
        ks_alias=None,
        ks_pass=None,
        recipe=None,
        tracker_db=None,
        yes=True,
        ai=False,
        ai_patch=False,
        output=None,
    )
    preview_res = pipeline.run_scan_or_clean(
        args, src_apk, mode="clean_preview", preview_dir=preview_dir, ops=cli
    )
    assert preview_res["ok"]
    assert "preview.diff" in {p.name for p in preview_res["artifacts"].values()}
    assert (preview_dir / "AndroidManifest.xml").is_file()

    # Merging splits without explicit -o writes to default_output outside TemporaryDirectory.
    default_out = tmp_path / "app-cleaned.apk"
    args.command = "clean"
    args.merge_splits = True
    monkeypatch.setattr(cli, "unpack", lambda s, w: [src_apk, src_apk])
    monkeypatch.setattr(
        cli,
        "merge_bundle",
        lambda a, parts, work, apkeditor, notes=None: _make_zip(work / "merged.apk", {"classes.dex": raw_dex}),
    )
    monkeypatch.setattr(cli, "rebuild_with", lambda req, act, r, u, **k: _make_zip(u, {"classes.dex": raw_dex}))
    monkeypatch.setattr(cli, "identity", lambda a: (tmp_path / "k.jks", "s", {}))
    monkeypatch.setattr(cli, "sign", lambda u, w, s, c: _make_zip(s, {"classes.dex": raw_dex}))

    clean_res = pipeline.run_scan_or_clean(
        args, bundle, mode="clean", default_output=default_out, ops=cli
    )
    assert clean_res["ok"] and not clean_res.get("noop")
    assert default_out.is_file()
    assert clean_res["output"] == str(default_out.resolve())
