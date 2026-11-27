"""Pure-Python local WebUI server and job runner for APK Surgeon."""

import hmac
import ipaddress
import json
import mimetypes
import re
import secrets
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import webbrowser
import zipfile
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, quote, unquote, urlsplit

from lxml.etree import XMLSyntaxError

from . import __version__, cli, engines, pipeline, recipe, toolkit, verify
from .bundles import unpack

ASSETS_DIR = Path(__file__).with_name("ui_assets")
UPLOAD_EXTENSIONS = {".apk", ".apks", ".xapk", ".apkm"}
MAX_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024
MAX_JSON_BODY_BYTES = 2 * 1024 * 1024
MAX_PREVIEW_BYTES = 2 * 1024 * 1024
MAX_LOG_LINES = 400
INLINE_TEXT_SUFFIXES = {".md", ".txt", ".xml", ".diff", ".json", ".yml", ".yaml", ".smali"}


class _LogBatcher:
    """Coalesce streaming subprocess output lines into bounded SSE updates."""

    def __init__(self, emit_fn, interval=0.25):
        self._emit_fn = emit_fn
        self._interval = interval
        self._lock = threading.Lock()
        self._buf = []
        self._timer = None
        self._closed = False

    def push(self, line):
        text = str(line).rstrip()
        if not text:
            return
        with self._lock:
            if self._closed:
                return
            self._buf.append(text)
            if len(self._buf) >= 20:
                batch = self._pop_locked()
            elif self._timer is None:
                self._timer = threading.Timer(self._interval, self.flush)
                self._timer.daemon = True
                self._timer.start()
                batch = None
            else:
                batch = None
        if batch:
            self._emit_fn(batch)

    def _pop_locked(self):
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        if not self._buf:
            return None
        batch = self._buf
        self._buf = []
        return batch

    def flush(self):
        with self._lock:
            batch = self._pop_locked()
        if batch:
            self._emit_fn(batch)

    def close(self):
        with self._lock:
            self._closed = True
            batch = self._pop_locked()
        if batch:
            self._emit_fn(batch)


def is_loopback_host(host):
    """True when ``host`` resolves cleanly as loopback without network exposure."""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def _safe_filename(filename):
    base = (filename or "upload.apk").replace("\\", "/").rsplit("/", 1)[-1]
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", base).strip(".")
    if not cleaned:
        cleaned = "upload.apk"
    suffix = Path(cleaned).suffix.lower()
    if suffix not in UPLOAD_EXTENSIONS:
        raise ValueError(f"Unsupported upload extension {suffix!r}; expected .apk, .apks, .xapk, or .apkm")
    return cleaned[:120]


def doctor_info(apkeditor_jar=None):
    """Collect live toolchain availability, versions, and OS install hints."""
    tools = []
    for name in cli.TOOLS:
        resolved = shutil.which(name)
        version = None
        warning = None
        if resolved and name == "apktool":
            try:
                version = subprocess.check_output(
                    [resolved, "--version"], stderr=subprocess.STDOUT, text=True, timeout=10
                ).strip()
                match = re.search(r"(\d+)\.(\d+)\.(\d+)", version)
                if not match or tuple(map(int, match.groups())) < (3, 0, 3):
                    warning = "Upgrade Apktool to 3.0.3 or newer (CVE-2026-39973 affects 3.0.0/3.0.1)."
            except (OSError, subprocess.SubprocessError) as error:
                version = "unknown"
                warning = f"apktool failed health check: {error}"
        tools.append({"name": name, "present": bool(resolved), "path": resolved, "version": version, "warning": warning})

    apkeditor_error = None
    apkeditor_target = None
    apkeditor_ver = None
    try:
        apkeditor_target = engines.resolve_apkeditor(apkeditor_jar)
        if apkeditor_target is not None:
            apkeditor_ver = engines.apkeditor_version(apkeditor_target)
    except engines.EngineError as error:
        apkeditor_error = str(error)

    return {
        "ok": True,
        "version": __version__,
        "tools": tools,
        "missing_required": [row["name"] for row in tools if not row["present"]],
        "apkeditor": {
            "present": apkeditor_target is not None,
            "path": str(apkeditor_target) if apkeditor_target else None,
            "version": apkeditor_ver,
            "download": engines.DOWNLOAD,
            "error": apkeditor_error,
        },
        "install_guides": {
            "linux": "sudo apt install default-jdk apktool apksigner zipalign aapt",
            "macos": "brew install openjdk apktool && brew install --cask android-commandlinetools",
            "windows": "winget install EclipseAdoptium.Temurin.17.JDK && sdkmanager \"build-tools;35.0.0\"",
            "termux": "pkg install openjdk-17 apksigner aapt2",
        },
        "install_text": cli.INSTALL,
    }


def _clean_args_from_payload(payload, *, work_dir, recipe_path=None):
    return SimpleNamespace(
        command="clean",
        apkeditor_jar=Path(payload["apkeditor_jar"]) if payload.get("apkeditor_jar") else None,
        engine=payload.get("engine") or "auto",
        smali_only=bool(payload.get("smali_only", False)),
        abi=payload.get("abi") or None,
        merge_splits=bool(payload.get("merge_splits", False)),
        selective_dex=bool(payload.get("selective_dex", False)),
        sinkhole=bool(payload.get("sinkhole", False)),
        trust_user_ca=bool(payload.get("trust_user_ca", False)),
        allow_screenshots=bool(payload.get("allow_screenshots", False)),
        strip_ad_permissions=bool(payload.get("strip_ad_permissions", False)),
        disable_providers=bool(payload.get("disable_providers", False)),
        allow_custom_domains=bool(payload.get("allow_custom_domains", False)),
        force_unsafe=bool(payload.get("force_unsafe", False)),
        keystore=payload.get("keystore") or None,
        ks_alias=payload.get("ks_alias") or None,
        ks_pass=payload.get("ks_pass") or None,
        recipe=recipe_path,
        tracker_db=None,
        yes=True,
        ai=False,
        ai_patch=False,
        llm_url="http://localhost:11434/v1",
        model="qwen3:4b",
        json=False,
        output=None,
    )


class JobManager:
    """Thread-safe workspace, upload registry, and background job manager with SSE."""

    def __init__(self, workspace=None):
        self._owns_temp = workspace is None
        self.workspace = (
            Path(tempfile.mkdtemp(prefix="apk-surgeon-ui-")) if workspace is None else Path(workspace)
        ).resolve()
        self.uploads_dir = self.workspace / "uploads"
        self.jobs_dir = self.workspace / "jobs"
        self.uploads_dir.mkdir(parents=True, exist_ok=True)
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.uploads = {}
        self.jobs = {}
        self.job_order = []

    def close(self):
        with self._lock:
            active = list(self.jobs.values())
        for job in active:
            ev = job.get("cancel_event")
            if ev is not None:
                ev.set()
            with job["pid_lock"]:
                pids = list(job["pids"])
            for pid in pids:
                engines.terminate_process_tree(pid)
            with job["cond"]:
                if job["status"] in {"queued", "running"}:
                    job["status"] = "cancelled"
                    job["step"] = "Cancelled"
                    job["progress"] = 100
                    job["finished_at"] = time.time()
                    if job["started_at"]:
                        job["elapsed_ms"] = int((job["finished_at"] - job["started_at"]) * 1000)
                    payload = self._serialize_job(job)
                    job["events"].append({"type": "done", "data": payload})
                    job["cond"].notify_all()
        if self._owns_temp and self.workspace.exists():
            shutil.rmtree(self.workspace, ignore_errors=True)

    def save_upload(self, filename, stream, content_length=None):
        safe = _safe_filename(filename)
        if content_length is not None and content_length > MAX_UPLOAD_BYTES:
            raise ValueError("Upload exceeds maximum 2 GiB limit")
        upload_id = uuid.uuid4().hex[:12]
        dest_dir = (self.uploads_dir / upload_id).resolve()
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = (dest_dir / safe).resolve()
        if not dest.is_relative_to(self.uploads_dir):
            raise ValueError("Invalid upload destination")
        written = 0
        with dest.open("wb") as out:
            if content_length is None:
                while True:
                    chunk = stream.read(65536)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > MAX_UPLOAD_BYTES:
                        raise ValueError("Upload exceeds maximum 2 GiB limit")
                    out.write(chunk)
            else:
                remaining = content_length
                while remaining > 0:
                    chunk = stream.read(min(65536, remaining))
                    if not chunk:
                        break
                    written += len(chunk)
                    remaining -= len(chunk)
                    out.write(chunk)
        if written == 0:
            shutil.rmtree(dest_dir, ignore_errors=True)
            raise ValueError("Uploaded file is empty")
        with self._lock:
            self.uploads[upload_id] = dest
        return {"upload_id": upload_id, "filename": safe, "size": written}

    def resolve_input(self, payload, *, allow_dir=False):
        upload_id = payload.get("upload_id")
        if upload_id:
            with self._lock:
                path = self.uploads.get(str(upload_id))
            if path is None or not path.is_file() or not path.resolve().is_relative_to(self.uploads_dir):
                raise ValueError(f"Unknown or expired upload_id: {upload_id}")
            return path
        raw = payload.get("directory" if allow_dir else "path") or payload.get("path")
        if not raw:
            raise ValueError("Provide an uploaded file or local path")
        target = Path(str(raw)).expanduser().resolve(strict=True)
        if allow_dir and not target.is_dir():
            raise ValueError(f"Directory not found: {target}")
        if not allow_dir and not target.is_file():
            raise ValueError(f"File not found: {target}")
        return target

    def submit(self, job_type, payload):
        valid = {"inspect", "scan", "clean_preview", "clean", "decode", "build", "merge", "sign", "verify"}
        if job_type not in valid:
            raise ValueError(f"Unknown job type: {job_type}")
        job_id = uuid.uuid4().hex[:12]
        job_dir = (self.jobs_dir / job_id).resolve()
        job_dir.mkdir(parents=True, exist_ok=True)
        job = {
            "id": job_id,
            "type": job_type,
            "status": "queued",
            "step": "Queued",
            "progress": 0,
            "created_at": time.time(),
            "started_at": None,
            "finished_at": None,
            "elapsed_ms": 0,
            "logs": [],
            "events": [],
            "cond": threading.Condition(),
            "cancel_event": threading.Event(),
            "pids": set(),
            "pid_lock": threading.Lock(),
            "dir": job_dir,
            "decoded_dir": None,
            "artifact_map": {},
            "artifacts": [],
            "result": None,
            "error": None,
            "summary": {},
        }
        with self._lock:
            self.jobs[job_id] = job
            self.job_order.insert(0, job_id)
        thread = threading.Thread(target=self._run_job, args=(job, payload), daemon=True)
        thread.start()
        return self._serialize_job(job)

    def get_job(self, job_id):
        with self._lock:
            return self.jobs.get(str(job_id))

    def list_jobs(self):
        with self._lock:
            jobs = [self.jobs[jid] for jid in self.job_order]
        return [self._serialize_job(job) for job in jobs]

    def _serialize_job(self, job):
        with job["cond"]:
            elapsed = job["elapsed_ms"]
            if job["started_at"] and not job["finished_at"]:
                elapsed = int((time.time() - job["started_at"]) * 1000)
            return {
                "id": job["id"],
                "type": job["type"],
                "status": job["status"],
                "step": job["step"],
                "progress": job["progress"],
                "elapsed_ms": elapsed,
                "logs": list(job["logs"]),
                "artifacts": list(job["artifacts"]),
                "decoded_dir": str(job["decoded_dir"]) if job["decoded_dir"] else None,
                "result": job["result"],
                "error": job["error"],
                "summary": dict(job["summary"]),
            }

    @staticmethod
    def _append_log(job, message):
        job["logs"].append({"ts": round(time.time(), 2), "message": str(message)})
        if len(job["logs"]) > MAX_LOG_LINES:
            del job["logs"][:-MAX_LOG_LINES]

    def _emit(self, job, *, step=None, progress=None, log=None, logs=None, event_type="state"):
        with job["cond"]:
            if step is not None:
                job["step"] = step
            if progress is not None:
                job["progress"] = progress
            if log is not None:
                self._append_log(job, log)
            if logs:
                for line in logs:
                    self._append_log(job, line)
            payload = self._serialize_job(job)
            job["events"].append({"type": event_type, "data": payload})
            job["cond"].notify_all()

    @staticmethod
    def _track_pid(job, pid, active):
        with job["pid_lock"]:
            if active:
                job["pids"].add(pid)
            else:
                job["pids"].discard(pid)
        if active and job["cancel_event"].is_set():
            engines.terminate_process_tree(pid)

    def cancel_job(self, job_id):
        job = self.get_job(job_id)
        if not job:
            return None
        with job["cond"]:
            status = job["status"]
            already_terminal = status in {"done", "error", "cancelled"}
            if not already_terminal:
                job["cancel_event"].set()
                was_queued = status == "queued"
                if was_queued:
                    job["status"] = "cancelled"
                    job["step"] = "Cancelled"
                    job["progress"] = 100
                    job["finished_at"] = time.time()
                    if job["started_at"]:
                        job["elapsed_ms"] = int((job["finished_at"] - job["started_at"]) * 1000)
                else:
                    job["step"] = "Cancelling..."
                self._append_log(job, "Cancellation requested by user.")
                payload = self._serialize_job(job)
                job["events"].append({"type": "done" if was_queued else "state", "data": payload})
                job["cond"].notify_all()
        if not already_terminal:
            with job["pid_lock"]:
                pids = list(job["pids"])
            for pid in pids:
                engines.terminate_process_tree(pid)
        return self._serialize_job(job)

    def _register_artifact(self, job, path, label, kind="file"):
        path = Path(path).resolve()
        if not path.is_file() or not path.is_relative_to(job["dir"]):
            return None
        artifact_id = path.name
        size = path.stat().st_size
        meta = {
            "id": artifact_id,
            "name": path.name,
            "label": label,
            "kind": kind,
            "size": size,
            "inline": path.suffix.lower() in INLINE_TEXT_SUFFIXES,
            "url": f"/api/jobs/{job['id']}/artifacts/{quote(artifact_id, safe='')}",
        }
        job["artifact_map"][artifact_id] = {"path": path, "meta": meta}
        job["artifacts"].append(meta)
        return meta

    @staticmethod
    def _format_job_error(error):
        if isinstance(error, subprocess.CalledProcessError):
            cmd_list = error.cmd if isinstance(error.cmd, (list, tuple)) else [str(error.cmd)]
            tool = Path(str(cmd_list[0])).name if cmd_list else "subprocess"
            parts = [
                part.strip()
                for part in (getattr(error, "stderr", None), getattr(error, "stdout", None), getattr(error, "output", None))
                if isinstance(part, str) and part.strip()
            ]
            detail = "\n".join(parts)
            if len(detail) > 1500:
                detail = detail[-1500:]
            return (
                f"{tool} failed (exit {error.returncode}):\n{detail}"
                if detail
                else f"{tool} failed (exit {error.returncode})."
            )
        return str(error) or type(error).__name__

    def _run_job(self, job, payload):
        job["started_at"] = time.time()
        with job["cond"]:
            if job["cancel_event"].is_set() or job["status"] == "cancelled":
                return
            job["status"] = "running"
        batcher = _LogBatcher(lambda lines: self._emit(job, logs=lines))
        self._emit(job, step="Starting", progress=5, log=f"Starting {job['type']} job {job['id']}...")
        try:
            if job["cancel_event"].is_set():
                raise engines.CancelledError("Job cancelled by user.")
            with engines.execution_hooks(
                on_line=batcher.push,
                cancel_event=job["cancel_event"],
                on_pid=lambda pid, active: self._track_pid(job, pid, active),
            ):
                result = self._dispatch(job, payload)
            batcher.close()
            if job["cancel_event"].is_set():
                raise engines.CancelledError("Job cancelled by user.")
            job["result"] = result
            job["finished_at"] = time.time()
            job["elapsed_ms"] = int((job["finished_at"] - job["started_at"]) * 1000)
            with job["cond"]:
                job["status"] = "done"
            done_step = (
                "Verification FAIL"
                if (job["type"] == "verify" and isinstance(result, dict) and not result.get("ok", True))
                else "Completed"
            )
            done_log = (
                "Verification finished with failures."
                if done_step != "Completed"
                else "Job finished successfully."
            )
            self._emit(job, step=done_step, progress=100, log=done_log, event_type="done")
        except engines.CancelledError as error:
            batcher.close()
            job["finished_at"] = time.time()
            job["elapsed_ms"] = int((job["finished_at"] - job["started_at"]) * 1000)
            with job["cond"]:
                job["status"] = "cancelled"
            self._emit(job, step="Cancelled", progress=100, log=str(error) or "Job cancelled.", event_type="done")
        except Exception as error:
            batcher.close()
            if job["cancel_event"].is_set():
                job["finished_at"] = time.time()
                job["elapsed_ms"] = int((job["finished_at"] - job["started_at"]) * 1000)
                with job["cond"]:
                    job["status"] = "cancelled"
                self._emit(job, step="Cancelled", progress=100, log="Job cancelled by user.", event_type="done")
                return
            msg = self._format_job_error(error)
            job["error"] = msg
            job["finished_at"] = time.time()
            job["elapsed_ms"] = int((job["finished_at"] - job["started_at"]) * 1000)
            with job["cond"]:
                job["status"] = "error"
            self._emit(job, step="Failed", progress=100, log=f"Error: {msg}", event_type="done")

    def _dispatch(self, job, payload):
        jtype = job["type"]
        if jtype == "inspect":
            src = self.resolve_input(payload)
            self._emit(job, step="Inspecting archive", progress=40, log=f"Reading {src.name}...")
            return toolkit.inspect_apk(src)
        if jtype == "verify":
            src = self.resolve_input(payload)
            self._emit(job, step="Verifying signatures & alignment", progress=40, log=f"Verifying {src.name}...")
            with tempfile.TemporaryDirectory() as tmp:
                parts = unpack(src, Path(tmp))
                res = verify.verify(parts)
            for row in res["apks"]:
                label = "PASS" if not row["errors"] else "FAIL"
                self._emit(job, log=f"{row['apk']}: {label} (aligned={row['aligned']})")
                for err in row["errors"]:
                    self._emit(job, log=f"Error: {row['apk']}: {err}")
            job["summary"] = {
                "verified_ok": res["ok"],
                "apks": len(res["apks"]),
                "failed": sum(1 for row in res["apks"] if row["errors"]),
            }
            return res
        if jtype == "decode":
            src = self.resolve_input(payload)
            out_dir = Path(payload["output"]).expanduser().resolve() if payload.get("output") else (
                job["dir"] / f"{src.stem}-decoded"
            )
            self._emit(job, step="Decoding APK", progress=35, log=f"Decoding {src.name} -> {out_dir}...")
            res = toolkit.decode_apk(
                src, out_dir,
                engine=payload.get("engine") or "auto",
                apkeditor_jar=payload.get("apkeditor_jar") or None,
                no_res=bool(payload.get("no_res", False)),
                no_src=bool(payload.get("no_src", False)),
                force=bool(payload.get("force", False)),
            )
            job["decoded_dir"] = Path(res["output"]).resolve()
            job["summary"] = {"engine": res["engine"], "decode_type": res["decode_type"] or "default"}
            return res
        if jtype == "build":
            src_dir = self.resolve_input(payload, allow_dir=True)
            out_file = (
                Path(payload["output"]).expanduser().resolve()
                if payload.get("output")
                else job["dir"] / f"{src_dir.name}-built.apk"
            )
            self._emit(job, step="Rebuilding & aligning", progress=45, log=f"Building {src_dir.name}...")
            res = toolkit.build_apk(
                src_dir, out_file,
                engine=payload.get("engine") or "auto",
                apkeditor_jar=payload.get("apkeditor_jar") or None,
                unsigned=bool(payload.get("unsigned", False)),
                force=bool(payload.get("force", False)),
                keystore=payload.get("keystore") or None,
                ks_alias=payload.get("ks_alias") or None,
                ks_pass=payload.get("ks_pass") or None,
            )
            if not res.get("ok") and res.get("signed", True):
                errs = [err for row in (res.get("verify") or {}).get("apks", []) for err in row.get("errors", [])]
                raise ValueError("Built APK failed verification: " + ("; ".join(errs) or "unknown verification error"))
            if out_file.is_relative_to(job["dir"]):
                self._register_artifact(job, out_file, "Built APK", kind="apk")
            job["summary"] = {"engine": res["engine"], "signed": res["signed"], "output_size": out_file.stat().st_size}
            return res
        if jtype == "merge":
            src = self.resolve_input(payload)
            out_file = (
                Path(payload["output"]).expanduser().resolve()
                if payload.get("output")
                else job["dir"] / f"{src.stem}-merged.apk"
            )
            self._emit(job, step="Merging split bundle", progress=35, log=f"Merging {src.name}...")
            res = toolkit.merge_bundle(
                src, out_file,
                abi=payload.get("abi") or None,
                apkeditor_jar=payload.get("apkeditor_jar") or None,
                unsigned=bool(payload.get("unsigned", False)),
                force=bool(payload.get("force", False)),
                keystore=payload.get("keystore") or None,
                ks_alias=payload.get("ks_alias") or None,
                ks_pass=payload.get("ks_pass") or None,
            )
            if not res.get("ok") and res.get("signed", True):
                errs = [err for row in (res.get("verify") or {}).get("apks", []) for err in row.get("errors", [])]
                raise ValueError("Merged APK failed verification: " + ("; ".join(errs) or "unknown verification error"))
            if out_file.is_relative_to(job["dir"]):
                self._register_artifact(job, out_file, "Merged Standalone APK", kind="apk")
            for warn in res["warnings"]:
                self._emit(job, log=f"Warning: {warn}")
            for note in res["notes"]:
                self._emit(job, log=note)
            job["summary"] = {"abis": res["abis"], "signed": res["signed"], "output_size": out_file.stat().st_size}
            return res
        if jtype == "sign":
            src = self.resolve_input(payload)
            out_file = (
                Path(payload["output"]).expanduser().resolve()
                if payload.get("output")
                else job["dir"] / f"{src.stem}-signed.apk"
            )
            self._emit(job, step="Aligning & signing APK", progress=45, log=f"Signing {src.name}...")
            res = toolkit.sign_apk(
                src, out_file,
                force=bool(payload.get("force", False)),
                keystore=payload.get("keystore") or None,
                ks_alias=payload.get("ks_alias") or None,
                ks_pass=payload.get("ks_pass") or None,
            )
            if not res.get("ok"):
                errs = [err for row in (res.get("verify") or {}).get("apks", []) for err in row.get("errors", [])]
                raise ValueError("Signed APK failed verification: " + ("; ".join(errs) or "unknown verification error"))
            if out_file.is_relative_to(job["dir"]):
                self._register_artifact(job, out_file, "Signed APK", kind="apk")
            certs = ((res.get("verify") or {}).get("apks") or [{}])[0].get("certificates_sha256", [])
            if certs:
                self._emit(job, log=f"Verified signature SHA-256: {certs[0]}")
            job["summary"] = {"input_size": src.stat().st_size, "output_size": out_file.stat().st_size}
            return res
        return self._run_scan_or_clean(job, payload, mode=jtype)

    def _run_scan_or_clean(self, job, payload, *, mode):
        src = self.resolve_input(payload)
        allow_custom = bool(payload.get("allow_custom_domains", False))
        loaded_recipe = None
        recipe_file = None
        if payload.get("recipe_yaml") and str(payload["recipe_yaml"]).strip():
            loaded_recipe = recipe.loads(payload["recipe_yaml"], allow_custom_domains=allow_custom)
            recipe_file = job["dir"] / "recipe.yml"
            recipe_file.write_text(payload["recipe_yaml"], encoding="utf-8")
            loaded_recipe.path = recipe_file
        args = _clean_args_from_payload(payload, work_dir=job["dir"], recipe_path=recipe_file)
        if payload.get("output"):
            args.output = Path(payload["output"])
        notes = []
        if allow_custom:
            custom = loaded_recipe.custom_sinkhole_domains if loaded_recipe else []
            msg = (
                "Warning: --allow-custom-domains enabled custom sinkhole domains: " + ", ".join(custom)
                if custom
                else "Warning: --allow-custom-domains enabled; non-allowlisted recipe domains are permitted."
            )
            notes.append(msg)
            self._emit(job, log=msg)

        bundle_in = src.suffix.lower() != ".apk"
        out_ext = ".apks" if bundle_in and not args.merge_splits else ".apk"
        default_output = job["dir"] / f"{src.stem}-cleaned{out_ext}"

        def _on_event(*, step=None, progress=None, log=None):
            self._emit(job, step=step, progress=progress, log=log)

        res = pipeline.run_scan_or_clean(
            args,
            src,
            mode=mode,
            loaded_recipe=loaded_recipe,
            notes=notes,
            default_output=default_output,
            overwrite_existing=True,
            on_event=_on_event,
            preview_dir=job["dir"],
            ops=cli,
        )
        artifacts = res.pop("artifacts", None) or {}
        if mode in {"scan", "clean_preview"}:
            if "diff" in artifacts:
                self._register_artifact(job, artifacts["diff"], "Unified Diff", kind="diff")
            if "manifest" in artifacts:
                self._register_artifact(job, artifacts["manifest"], "Decoded AndroidManifest.xml", kind="manifest")
        else:
            if res.get("output"):
                out_path = Path(res["output"])
                if out_path.is_relative_to(job["dir"]):
                    self._register_artifact(job, out_path, "Cleaned APK", kind="apk")
            if res.get("report"):
                report_path = Path(res["report"])
                if report_path.is_relative_to(job["dir"]):
                    self._register_artifact(job, report_path, "Privacy Report", kind="report")
            if "diff" in artifacts:
                self._register_artifact(job, artifacts["diff"], "Patch Diff", kind="diff")
        if res.get("summary"):
            job["summary"] = dict(res["summary"])
        return res


def _make_handler(manager, token, allowed_hosts_fn):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format, *args):
            return

        def _send_json(self, status, payload):
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _send_bytes(self, status, content_type, body, *, extra_headers=None):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            for k, v in (extra_headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _check_origin_and_host(self):
            allowed = allowed_hosts_fn()
            host = (self.headers.get("Host") or "").strip().lower()
            if not host or host not in allowed:
                self._send_json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "Invalid Host header"})
                return False
            origin = self.headers.get("Origin")
            if origin:
                parts = urlsplit(origin.strip())
                if parts.scheme != "http" or parts.netloc.lower() not in allowed:
                    self._send_json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "Cross-origin request rejected"})
                    return False
            return True

        def _check_csrf(self):
            supplied = (self.headers.get("X-APK-Surgeon-Token") or "").strip()
            if not hmac.compare_digest(supplied, token):
                self._send_json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "Invalid or missing session CSRF token"})
                return False
            return True

        def _read_json(self):
            length_raw = self.headers.get("Content-Length")
            if not length_raw or not length_raw.isdigit():
                raise ValueError("Missing Content-Length")
            length = int(length_raw)
            if length > MAX_JSON_BODY_BYTES:
                raise ValueError("Request body too large")
            raw = self.rfile.read(length)
            data = json.loads(raw.decode("utf-8") or "{}")
            if not isinstance(data, dict):
                raise ValueError("Expected JSON object")
            return data

        def do_GET(self):
            if not self._check_origin_and_host():
                return
            parsed = urlsplit(self.path)
            path = unquote(parsed.path)
            if path == "/":
                html = (ASSETS_DIR / "index.html").read_text(encoding="utf-8")
                rendered = html.replace("__APK_SURGEON_TOKEN__", token).encode("utf-8")
                csp = (
                    "default-src 'self'; script-src 'self'; style-src 'self'; "
                    "img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
                )
                self._send_bytes(
                    HTTPStatus.OK,
                    "text/html; charset=utf-8",
                    rendered,
                    extra_headers={"Cache-Control": "no-store", "Content-Security-Policy": csp},
                )
                return
            if path.startswith("/assets/"):
                rel = path[len("/assets/"):]
                target = (ASSETS_DIR / rel).resolve()
                bad_asset = (
                    not rel or "/" in rel or "\\" in rel
                    or not target.is_relative_to(ASSETS_DIR.resolve())
                    or not target.is_file()
                )
                if bad_asset:
                    self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Asset not found"})
                    return
                ctype, _ = mimetypes.guess_type(target.name)
                self._send_bytes(
                    HTTPStatus.OK,
                    f"{ctype or 'application/octet-stream'}; charset=utf-8",
                    target.read_bytes(),
                    extra_headers={"Cache-Control": "no-store"},
                )
                return
            try:
                if path == "/api/doctor":
                    self._send_json(HTTPStatus.OK, doctor_info(None))
                    return
                if path == "/api/jobs":
                    self._send_json(HTTPStatus.OK, {"ok": True, "jobs": manager.list_jobs()})
                    return
                if path == "/api/workspace-file":
                    self._handle_workspace_file(parse_qs(parsed.query))
                    return
                match_events = re.fullmatch(r"/api/jobs/([A-Za-z0-9_-]+)/events", path)
                if match_events:
                    self._handle_sse(match_events.group(1))
                    return
                match_files = re.fullmatch(r"/api/jobs/([A-Za-z0-9_-]+)/files", path)
                if match_files:
                    self._handle_job_files(match_files.group(1))
                    return
                match_art = re.fullmatch(r"/api/jobs/([A-Za-z0-9_-]+)/artifacts/([^/]+)", path)
                if match_art:
                    qs = parse_qs(parsed.query)
                    self._handle_artifact(match_art.group(1), match_art.group(2), inline=qs.get("inline") == ["1"])
                    return
                match_job = re.fullmatch(r"/api/jobs/([A-Za-z0-9_-]+)", path)
                if match_job:
                    job = manager.get_job(match_job.group(1))
                    if not job:
                        self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Job not found"})
                        return
                    with job["cond"]:
                        self._send_json(HTTPStatus.OK, {"ok": True, "job": manager._serialize_job(job)})
                    return
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Not found"})
            except (ValueError, OSError, XMLSyntaxError, zipfile.BadZipFile, engines.EngineError,
                    subprocess.SubprocessError, struct.error) as error:
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": manager._format_job_error(error)})
            except Exception as error:
                self._send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"ok": False, "error": f"Internal server error: {error}"},
                )

        def _handle_workspace_file(self, query):
            job_id = (query.get("job_id") or [""])[0]
            rel = (query.get("path") or [""])[0]
            job = manager.get_job(job_id)
            if not job or not job["decoded_dir"]:
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Decoded workspace not found"})
                return
            if not rel or "\x00" in rel or Path(rel).is_absolute():
                self._send_json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "Invalid workspace path"})
                return
            root = job["decoded_dir"].resolve()
            target = (root / rel).resolve()
            if not target.is_relative_to(root):
                self._send_json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "Path escapes workspace"})
                return
            if not target.is_file():
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "File not found"})
                return
            data = target.read_bytes()[:MAX_PREVIEW_BYTES]
            self._send_json(HTTPStatus.OK, {"ok": True, "path": rel, "content": data.decode("utf-8", errors="replace")})

        def _handle_job_files(self, job_id):
            job = manager.get_job(job_id)
            if not job or not job["decoded_dir"]:
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Decoded workspace not found"})
                return
            root = job["decoded_dir"].resolve()
            interesting = []
            priority = [root / "AndroidManifest.xml", root / "apktool.yml", root / "archive-info.json"]
            seen = set()
            for item in priority:
                if item.is_file():
                    rel_item = item.relative_to(root).as_posix()
                    interesting.append(rel_item)
                    seen.add(rel_item)
            for p in sorted(root.rglob("*")):
                if not p.is_file():
                    continue
                if p.suffix.lower() in {".xml", ".yml", ".json", ".smali", ".txt"}:
                    rel_p = p.relative_to(root).as_posix()
                    if rel_p not in seen:
                        interesting.append(rel_p)
                        seen.add(rel_p)
                    if len(interesting) >= 300:
                        break
            self._send_json(HTTPStatus.OK, {"ok": True, "files": interesting})

        def _handle_artifact(self, job_id, artifact_id, *, inline=False):
            job = manager.get_job(job_id)
            if not job:
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Job not found"})
                return
            record = job["artifact_map"].get(artifact_id)
            if not record:
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Artifact not found"})
                return
            target = record["path"].resolve()
            if not target.is_relative_to(job["dir"].resolve()) or not target.is_file():
                self._send_json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "Artifact path out of bounds"})
                return
            if inline and target.suffix.lower() in INLINE_TEXT_SUFFIXES:
                text = target.read_bytes()[:MAX_PREVIEW_BYTES].decode("utf-8", errors="replace")
                self._send_json(HTTPStatus.OK, {"ok": True, "name": target.name, "content": text})
                return
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(target.stat().st_size))
            safe_disp = re.sub(r'[^A-Za-z0-9._-]', "_", target.name) or "artifact.bin"
            self.send_header("Content-Disposition", f'attachment; filename="{safe_disp}"')
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            with target.open("rb") as stream:
                shutil.copyfileobj(stream, self.wfile)

        def _handle_sse(self, job_id):
            job = manager.get_job(job_id)
            if not job:
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Job not found"})
                return
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            cursor = 0
            try:
                while True:
                    with job["cond"]:
                        while cursor >= len(job["events"]) and job["status"] in {"queued", "running"}:
                            if not job["cond"].wait(timeout=15.0):
                                break
                        batch = job["events"][cursor:]
                        cursor += len(batch)
                        finished = job["status"] in {"done", "error", "cancelled"} and cursor >= len(job["events"])
                    if not batch and not finished:
                        self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
                        continue
                    for ev in batch:
                        frame = f"event: {ev['type']}\ndata: {json.dumps(ev['data'])}\n\n".encode()
                        self.wfile.write(frame)
                    self.wfile.flush()
                    if finished:
                        break
            except (BrokenPipeError, ConnectionResetError, OSError):
                return

        def do_POST(self):
            if not self._check_origin_and_host() or not self._check_csrf():
                return
            path = unquote(urlsplit(self.path).path)
            try:
                if path == "/api/upload":
                    length_raw = self.headers.get("Content-Length")
                    if not length_raw or not length_raw.isdigit():
                        raise ValueError("Missing Content-Length header on upload")
                    content_length = int(length_raw)
                    filename = self.headers.get("X-Filename") or "upload.apk"
                    res = manager.save_upload(filename, self.rfile, content_length=content_length)
                    self._send_json(HTTPStatus.OK, {"ok": True, **res})
                    return
                payload = self._read_json()
                if path == "/api/doctor":
                    self._send_json(HTTPStatus.OK, doctor_info(payload.get("apkeditor_jar") or None))
                    return
                if path == "/api/inspect":
                    src = manager.resolve_input(payload)
                    self._send_json(HTTPStatus.OK, toolkit.inspect_apk(src))
                    return
                if path == "/api/detect-engine":
                    directory = manager.resolve_input(payload, allow_dir=True)
                    engine = toolkit.detect_decoded_engine(directory, requested=payload.get("engine") or "auto")
                    self._send_json(HTTPStatus.OK, {"ok": True, "engine": engine})
                    return
                if path == "/api/recipe/validate":
                    allow_custom = bool(payload.get("allow_custom_domains", False))
                    parsed = recipe.loads(payload.get("yaml") or "", allow_custom_domains=allow_custom)
                    self._send_json(HTTPStatus.OK, {
                        "ok": True,
                        "valid": True,
                        "summary": {
                            "package_prefixes": len(parsed.package_prefixes),
                            "methods": sum(len(v) for v in parsed.methods.values()),
                            "disable_components": len(parsed.disable_components),
                            "sinkhole_domains": parsed.sinkhole_domains,
                            "custom_domains": parsed.custom_sinkhole_domains,
                        },
                    })
                    return
                match_cancel = re.fullmatch(r"/api/jobs/([A-Za-z0-9_-]+)/cancel", path)
                if match_cancel:
                    job = manager.cancel_job(match_cancel.group(1))
                    if not job:
                        self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Job not found"})
                        return
                    self._send_json(HTTPStatus.OK, {"ok": True, "job": job})
                    return
                if path == "/api/jobs":
                    job = manager.submit(payload.get("type", ""), payload)
                    self._send_json(HTTPStatus.ACCEPTED, {"ok": True, "job": job})
                    return
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Not found"})
            except (ValueError, OSError, XMLSyntaxError, zipfile.BadZipFile, engines.EngineError,
                    subprocess.SubprocessError, struct.error) as error:
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": manager._format_job_error(error)})
            except Exception as error:
                self._send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"ok": False, "error": f"Internal server error: {error}"},
                )

        def do_PUT(self):
            self._check_origin_and_host() and self._check_csrf() and self._send_json(
                HTTPStatus.METHOD_NOT_ALLOWED, {"ok": False, "error": "Method not allowed"}
            )

        def do_DELETE(self):
            self._check_origin_and_host() and self._check_csrf() and self._send_json(
                HTTPStatus.METHOD_NOT_ALLOWED, {"ok": False, "error": "Method not allowed"}
            )

    return Handler


def create_server(host="127.0.0.1", port=8765, *, workspace=None):
    """Create the hardened local UI server without starting the accept loop."""
    if not is_loopback_host(host):
        print(
            f"Warning: binding apk-surgeon ui to non-loopback host {host!r} exposes local APK files "
            "and build execution over the network!",
            file=sys.stderr,
        )
    manager = JobManager(workspace=workspace)
    token = secrets.token_urlsafe(32)

    class Server(ThreadingHTTPServer):
        daemon_threads = True
        allow_reuse_address = True

        def handle_error(self, request, client_address):
            exc = sys.exc_info()[1]
            if isinstance(exc, (ConnectionAbortedError, ConnectionResetError, BrokenPipeError)):
                return
            super().handle_error(request, client_address)

    bound_hosts = {host.lower()}
    if host in {"127.0.0.1", "localhost"}:
        bound_hosts |= {"127.0.0.1", "localhost"}
    elif host in {"::1", "[::1]"}:
        bound_hosts |= {"::1", "[::1]"}

    def allowed_hosts():
        actual_port = httpd.server_port
        out = set()
        for h in bound_hosts:
            out.add(h)
            out.add(f"{h}:{actual_port}")
        return out

    handler = _make_handler(manager, token, allowed_hosts)
    httpd = Server((host, int(port)), handler)
    httpd.csrf_token = token
    httpd.manager = manager
    orig_close = httpd.server_close

    def close_all():
        try:
            orig_close()
        finally:
            manager.close()

    httpd.server_close = close_all
    return httpd


def serve(host="127.0.0.1", port=8765, *, open_browser=True, workspace=None):
    """Run the APK Surgeon local WebUI server until interrupted."""
    httpd = create_server(host=host, port=port, workspace=workspace)
    display_host = "127.0.0.1" if host in {"0.0.0.0", ""} else host
    url = f"http://{display_host}:{httpd.server_port}/"
    print(f"APK Surgeon UI running at {url}", flush=True)
    print("Press Ctrl+C to stop.", flush=True)
    if open_browser:
        threading.Timer(0.2, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
        httpd.server_close()
    return 0
