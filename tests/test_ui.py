"""Tests for the apk-surgeon local WebUI server, security guards, SSE, and packaging."""

import http.client
import json
import re
import subprocess
import sys
import threading
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from apk_surgeon import cli, engines, ui


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


def test_ui_serves_html_token_csp_and_static_assets(live_ui):
    _, base, token = live_ui
    status, headers, body = _req(f"{base}/")
    assert status == 200
    html = body.decode("utf-8")
    assert f'<meta name="apk-surgeon-token" content="{token}">' in html
    assert "Content-Security-Policy" in headers
    assert "script-src 'self'" in headers["Content-Security-Policy"]
    assert headers.get("X-Content-Type-Options") == "nosniff"

    for asset in ("app.css", "app.js"):
        st, _, raw = _req(f"{base}/assets/{asset}")
        assert st == 200 and len(raw) > 200

    st_miss, _, _ = _req(f"{base}/assets/missing.js")
    assert st_miss == 404


def test_ui_security_csrf_origin_host_and_xss_hygiene(live_ui, tmp_path, dex_bytes):
    server, base, token = live_ui
    apk = _make_apk(tmp_path / "app.apk", {"classes.dex": dex_bytes(["a"])})
    payload = json.dumps({"path": str(apk)}).encode("utf-8")

    # Missing or wrong CSRF token -> 403
    for bad_hdrs in (
        {"Content-Type": "application/json"},
        {"Content-Type": "application/json", "X-APK-Surgeon-Token": "wrong-token"},
    ):
        st, _, data = _req(f"{base}/api/inspect", method="POST", body=payload, headers=bad_hdrs)
        assert st == 403 and json.loads(data)["ok"] is False

    # Bad Origin -> 403
    st_origin, _, _ = _req(
        f"{base}/api/inspect",
        method="POST",
        body=payload,
        headers={
            "Content-Type": "application/json",
            "X-APK-Surgeon-Token": token,
            "Origin": "http://evil.example",
        },
    )
    assert st_origin == 403

    # DNS-rebinding Host header -> 403
    conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    conn.request("GET", "/api/doctor", headers={"Host": "evil.attacker:8765"})
    resp = conn.getresponse()
    assert resp.status == 403
    conn.close()

    # Path traversal on /assets and /api/workspace-file -> rejected
    conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    conn.request("GET", "/assets/%2e%2e/ui.py", headers={"Host": f"127.0.0.1:{server.server_port}"})
    assert conn.getresponse().status == 404
    conn.close()

    # Verify static UI assets contain zero unsafe DOM HTML sinks
    assets = Path(__file__).resolve().parents[1] / "apk_surgeon/ui_assets"
    for name in ("app.js", "index.html"):
        text = (assets / name).read_text(encoding="utf-8")
        assert "innerHTML" not in text
        assert "outerHTML" not in text
        assert "insertAdjacentHTML" not in text
        assert "document.write" not in text
        assert not re.search(r"\beval\s*\(", text)


def test_non_loopback_host_emits_warning(tmp_path, capsys):
    srv = ui.create_server(host="0.0.0.0", port=0, workspace=tmp_path / "net-work")
    try:
        err = capsys.readouterr().err
        assert "non-loopback host" in err
    finally:
        srv.server_close()


def test_doctor_recipe_upload_and_inspect_endpoints(live_ui, tmp_path, monkeypatch, dex_container_bytes):
    _, base, token = live_ui

    st, _, doc_body = _req(f"{base}/api/doctor")
    doc = json.loads(doc_body)
    assert st == 200 and doc["ok"] and "tools" in doc and "install_guides" in doc

    # POST /api/doctor enforces CSRF token and supports explicit apkeditor_jar check
    st_no_csrf, _, _ = _req(
        f"{base}/api/doctor",
        method="POST",
        body=json.dumps({"apkeditor_jar": str(tmp_path / "missing.jar")}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    assert st_no_csrf == 403
    st_post_doc, _, post_doc_body = _req(
        f"{base}/api/doctor",
        method="POST",
        body=json.dumps({"apkeditor_jar": str(tmp_path / "missing.jar")}).encode("utf-8"),
        headers={"X-APK-Surgeon-Token": token, "Content-Type": "application/json"},
    )
    assert st_post_doc == 200 and "not found" in (json.loads(post_doc_body)["apkeditor"]["error"] or "")

    # Upload APK containing DEX 041 container + XSS string inside aapt2 mocked output
    apk = _make_apk(tmp_path / "xss.apk", {
        "classes.dex": dex_container_bytes([["a"], ["https://app-measurement.com/a"]]),
        "lib/arm64-v8a/libflutter.so": b"\x7fELF",
    })
    raw_bytes = apk.read_bytes()
    st_up, _, up_body = _req(
        f"{base}/api/upload",
        method="POST",
        body=raw_bytes,
        headers={
            "X-APK-Surgeon-Token": token,
            "X-Filename": "../../weird<name>.apk",
            "Content-Type": "application/octet-stream",
        },
    )
    up = json.loads(up_body)
    assert st_up == 200 and up["ok"]
    assert ".." not in up["filename"] and "/" not in up["filename"]

    # Reject disallowed upload extension
    st_bad_ext, _, _ = _req(
        f"{base}/api/upload",
        method="POST",
        body=b"mz",
        headers={"X-APK-Surgeon-Token": token, "X-Filename": "bad.exe"},
    )
    assert st_bad_ext == 400

    # Inspect uploaded APK with mocked aapt2 carrying XSS payload (raw JSON must serialize safely)
    monkeypatch.setattr("apk_surgeon.toolkit.shutil.which", lambda n: "/usr/bin/aapt2")
    monkeypatch.setattr(
        "apk_surgeon.toolkit.subprocess.run",
        Mock(return_value=SimpleNamespace(
            returncode=0,
            stdout="package: name='com.evil.<script>' versionCode='1'\napplication-label:'<img src=x onerror=alert(1)>'\n",
        )),
    )
    st_ins, _, ins_body = _req(
        f"{base}/api/inspect",
        method="POST",
        body=json.dumps({"upload_id": up["upload_id"]}).encode("utf-8"),
        headers={"X-APK-Surgeon-Token": token, "Content-Type": "application/json"},
    )
    ins = json.loads(ins_body)
    assert st_ins == 200 and ins["ok"]
    assert ins["dex_files"][0]["container_sections"] == 2
    assert ins["detected_frameworks"] == ["Flutter"]
    assert ins["badging"]["package"] == "com.evil.<script>"

    # Recipe validation endpoint
    st_bad, _, bad_rec = _req(
        f"{base}/api/recipe/validate",
        method="POST",
        body=json.dumps({"yaml": "version: 1\nsinkhole_domains: [custom.example.com]\n"}).encode("utf-8"),
        headers={"X-APK-Surgeon-Token": token, "Content-Type": "application/json"},
    )
    assert st_bad == 400 and "allowlist" in json.loads(bad_rec)["error"]

    st_ok, _, ok_rec = _req(
        f"{base}/api/recipe/validate",
        method="POST",
        body=json.dumps({
            "yaml": "version: 1\nsinkhole_domains: [custom.example.com]\n",
            "allow_custom_domains": True,
        }).encode("utf-8"),
        headers={"X-APK-Surgeon-Token": token, "Content-Type": "application/json"},
    )
    ok_json = json.loads(ok_rec)
    assert st_ok == 200 and ok_json["valid"] and ok_json["summary"]["custom_domains"] == ["custom.example.com"]


def test_job_sse_clean_preview_artifacts_and_workspace_confinement(live_ui, tmp_path, monkeypatch, dex_bytes):
    server, base, token = live_ui
    apk = _make_apk(tmp_path / "target.apk", {"classes.dex": dex_bytes(["https://app-measurement.com/a"])})
    dec_root = tmp_path / "fake-decoded"
    (dec_root / "smali/com/example").mkdir(parents=True)
    (dec_root / "smali/com/example/A.smali").write_text(
        '.class public Lcom/example/A;\n.method a()V\n    .locals 1\n'
        '    const-string v0, "https://app-measurement.com/a"\n    return-void\n.end method\n'
    )
    (dec_root / "AndroidManifest.xml").write_text('<manifest package="org.example"><application/></manifest>')
    monkeypatch.setattr(cli.engines, "decode_apktool", lambda *a, **k: engines.DecodeResult("apktool", dec_root))

    st, _, body = _req(
        f"{base}/api/jobs",
        method="POST",
        body=json.dumps({"type": "clean_preview", "path": str(apk), "sinkhole": True}).encode("utf-8"),
        headers={"X-APK-Surgeon-Token": token, "Content-Type": "application/json"},
    )
    assert st == 202
    job_id = json.loads(body)["job"]["id"]

    # Read real SSE stream to completion
    with urllib.request.urlopen(f"{base}/api/jobs/{job_id}/events", timeout=5) as stream:
        sse_text = stream.read().decode("utf-8")
    assert "event: done" in sse_text
    assert '"status": "done"' in sse_text

    # Fetch job & artifact
    st_j, _, job_body = _req(f"{base}/api/jobs/{job_id}")
    job = json.loads(job_body)["job"]
    assert st_j == 200 and job["status"] == "done"
    assert job["result"]["stats"]["sinkholed"] == ["https://app-measurement.com/a"]
    diff_art = next(a for a in job["artifacts"] if a["name"] == "preview.diff")

    st_inl, _, inl_body = _req(f"{base}{diff_art['url']}?inline=1")
    assert st_inl == 200 and "127.0.0.1" in json.loads(inl_body)["content"]

    st_dl, dl_hdrs, dl_bytes = _req(f"{base}{diff_art['url']}")
    assert st_dl == 200 and "attachment" in dl_hdrs.get("Content-Disposition", "") and b"127.0.0.1" in dl_bytes

    # Simulate decoded workspace file browsing & verify traversal outside decoded_dir is blocked
    secret = tmp_path / "outside-secret.txt"
    secret.write_text("TOP_SECRET")
    job_obj = server.manager.get_job(job_id)
    job_obj["decoded_dir"] = dec_root

    st_files, _, files_body = _req(f"{base}/api/jobs/{job_id}/files")
    assert st_files == 200 and json.loads(files_body)["files"][0] == "AndroidManifest.xml"

    st_ok_file, _, manifest_body = _req(f"{base}/api/workspace-file?job_id={job_id}&path=AndroidManifest.xml")
    assert st_ok_file == 200 and "org.example" in json.loads(manifest_body)["content"]

    st_escape, _, _ = _req(f"{base}/api/workspace-file?job_id={job_id}&path=../outside-secret.txt")
    assert st_escape == 403


def test_ui_cli_help_subprocess_banner_and_package_data_bundling():
    res = subprocess.run([sys.executable, "-m", "apk_surgeon.cli", "ui", "--help"], capture_output=True, text=True)
    assert res.returncode == 0
    assert "--host" in res.stdout and "--port" in res.stdout and "--no-browser" in res.stdout

    proc = subprocess.Popen(
        [sys.executable, "-m", "apk_surgeon.cli", "ui", "--no-browser", "--port", "0"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        banner = proc.stdout.readline().strip()
        m = re.search(r"(http://127\.0\.0\.1:\d+/)", banner)
        assert m, f"Expected immediate flushed startup URL banner, got: {banner!r}"
        st, _, html = _req(m.group(1))
        assert st == 200 and b"apk-surgeon-token" in html
    finally:
        proc.terminate()
        proc.wait(timeout=5)

    root = Path(__file__).resolve().parents[1]
    pyproject_text = (root / "pyproject.toml").read_text(encoding="utf-8")
    assert '"ui_assets/*"' in pyproject_text
    for asset in ("index.html", "app.css", "app.js"):
        assert (root / "apk_surgeon/ui_assets" / asset).is_file()
