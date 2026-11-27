"""Pure-Python local WebUI server and job runner for APK Surgeon."""

import hmac
import ipaddress
import itertools
import json
import mimetypes
import re
import secrets
import shutil
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
from urllib.parse import parse_qs, unquote, urlsplit

from lxml.etree import XMLSyntaxError

from . import __version__, cli, engines, frameworks, patcher, recipe, signing, sinkhole, toolkit, verify
from .bundles import select_abi, unpack

ASSETS_DIR = Path(__file__).with_name("ui_assets")
UPLOAD_EXTENSIONS = {".apk", ".apks", ".xapk", ".apkm"}
MAX_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024
MAX_JSON_BODY_BYTES = 2 * 1024 * 1024
MAX_PREVIEW_BYTES = 2 * 1024 * 1024
MAX_DIFF_LINES = 2500
INLINE_TEXT_SUFFIXES = {".md", ".txt", ".xml", ".diff", ".json", ".yml", ".yaml", ".smali"}


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
                version = subprocess.check_output(["apktool", "--version"], text=True, timeout=10).strip()
                match = re.search(r"(\d+)\.(\d+)\.(\d+)", version)
                if not match or tuple(map(int, match.groups())) < (3, 0, 3):
                    warning = "Upgrade Apktool to 3.0.3 or newer (CVE-2026-39973 affects 3.0.0/3.0.1)."
            except (OSError, subprocess.SubprocessError):
                version = "unknown"
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
            return [self._serialize_job(self.jobs[jid]) for jid in self.job_order]

    def _serialize_job(self, job):
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
            "summary": job["summary"],
        }

    def _emit(self, job, *, step=None, progress=None, log=None, event_type="state"):
        with job["cond"]:
            if step is not None:
                job["step"] = step
            if progress is not None:
                job["progress"] = progress
            if log is not None:
                entry = {"ts": round(time.time(), 2), "message": str(log)}
                job["logs"].append(entry)
            payload = self._serialize_job(job)
            job["events"].append({"type": event_type, "data": payload})
            job["cond"].notify_all()

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
            "url": f"/api/jobs/{job['id']}/artifacts/{artifact_id}",
        }
        job["artifact_map"][artifact_id] = {"path": path, "meta": meta}
        job["artifacts"].append(meta)
        return meta

    def _run_job(self, job, payload):
        job["started_at"] = time.time()
        with job["cond"]:
            job["status"] = "running"
        self._emit(job, step="Starting", progress=5, log=f"Starting {job['type']} job {job['id']}...")
        try:
            result = self._dispatch(job, payload)
            job["result"] = result
            job["finished_at"] = time.time()
            job["elapsed_ms"] = int((job["finished_at"] - job["started_at"]) * 1000)
            with job["cond"]:
                job["status"] = "done"
            self._emit(job, step="Completed", progress=100, log="Job finished successfully.", event_type="done")
        except (
            OSError, ValueError, KeyError, XMLSyntaxError, zipfile.BadZipFile,
            subprocess.CalledProcessError, engines.EngineError,
        ) as error:
            job["error"] = str(error)
            job["finished_at"] = time.time()
            job["elapsed_ms"] = int((job["finished_at"] - job["started_at"]) * 1000)
            with job["cond"]:
                job["status"] = "error"
            self._emit(job, step="Failed", progress=100, log=f"Error: {error}", event_type="done")

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
                return verify.verify(parts)
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
            if out_file.is_relative_to(job["dir"]):
                self._register_artifact(job, out_file, "Signed APK", kind="apk")
            job["summary"] = {"input_size": src.stat().st_size, "output_size": out_file.stat().st_size}
            return res
        return self._run_scan_or_clean(job, payload, mode=jtype)

    def _run_scan_or_clean(self, job, payload, *, mode):
        src = self.resolve_input(payload)
        input_size = src.stat().st_size
        allow_custom = bool(payload.get("allow_custom_domains", False))
        loaded_recipe = None
        recipe_file = None
        if payload.get("recipe_yaml") and str(payload["recipe_yaml"]).strip():
            loaded_recipe = recipe.loads(payload["recipe_yaml"], allow_custom_domains=allow_custom)
            recipe_file = job["dir"] / "recipe.yml"
            recipe_file.write_text(payload["recipe_yaml"], encoding="utf-8")
            loaded_recipe.path = recipe_file
        args = _clean_args_from_payload(payload, work_dir=job["dir"], recipe_path=recipe_file)
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

        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp)
            self._emit(job, step="Unpacking input", progress=15, log=f"Unpacking {src.name}...")
            parts = unpack(src, work)
            bundle = src.suffix.lower() != ".apk"
            apkeditor = engines.resolve_apkeditor(args.apkeditor_jar)
            bypass = args.smali_only

            if args.abi and not bundle:
                raise ValueError("--abi requires a split bundle")
            if args.merge_splits and not bundle:
                raise ValueError("--merge-splits requires a .xapk, .apkm or .apks bundle")
            if args.merge_splits:
                parts, _ = select_abi(parts, args.abi)
                self._emit(job, step="Merging splits", progress=25, log="Merging splits with APKEditor...")
                built = cli.merge_bundle(args, parts, work, apkeditor, notes=notes)
                parts, bundle = [built], False
            elif bundle:
                parts, found = select_abi(parts, args.abi)
                if len(found) > 1 and not args.abi:
                    notes.append("Multiple ABIs detected (" + ", ".join(found) + "); filtering with --abi is recommended.")

            detected = frameworks.detect(parts)
            blocked, blocked_reasons = frameworks.pairip_detected(parts)
            if blocked and mode == "clean" and not args.force_unsafe:
                raise ValueError(
                    "Refusing to patch a Pairip-protected APK. Use RethinkDNS/TrackerControl or pass "
                    "--force-unsafe to override at your own risk."
                )
            if blocked and mode == "clean" and args.force_unsafe:
                notes.append("Pairip BLOCKED overridden with --force-unsafe.")

            if args.selective_dex and (
                args.strip_ad_permissions or args.disable_providers or args.trust_user_ca
                or (loaded_recipe and loaded_recipe.disable_components)
            ):
                raise ValueError("--selective-dex patches DEX files only and cannot edit AndroidManifest.xml")

            selective_result = None
            if mode == "clean" and (args.selective_dex or (bypass and not args.trust_user_ca)):
                self._emit(job, step="Selective DEX scan", progress=40, log="Scanning DEX string pools...")
                selective_result = cli.selective_clean(args, parts[0], work, loaded_recipe, notes)

            if selective_result:
                staged, backups = selective_result
                evidence, safety = cli.assess_for_selective(staged, parts[1:], loaded_recipe)
                families = sorted(evidence)
                if not backups:
                    return {"noop": True, "notes": notes, "safety": safety, "privacy_score": max(0, 100 - 4 * len(families))}
                out_ext = ".apks" if bundle else ".apk"
                out = (
                    Path(payload["output"]).expanduser().resolve()
                    if payload.get("output")
                    else job["dir"] / f"{src.stem}-cleaned{out_ext}"
                )
                if out == src.resolve():
                    raise ValueError("Refusing to modify input APK in place")
                out.parent.mkdir(parents=True, exist_ok=True)
                report = out.parent / "privacy-report.md"
                backup = out.with_suffix(".backups")
                backup.mkdir(exist_ok=True)
                with zipfile.ZipFile(parts[0]) as archive:
                    for name, _ in backups:
                        (backup / (name + ".bak")).write_bytes(archive.read(name))
                self._emit(job, step="Signing output", progress=80, log="Aligning & signing selective APK...")
                signed = work / "signed.apk"
                creds = signing.resolve_identity(keystore=args.keystore, ks_alias=args.ks_alias, ks_pass=args.ks_pass)
                signing.sign(staged, work, signed, creds)
                if bundle:
                    signed = cli._pack_bundle(signed, parts, work, creds)
                shutil.copyfile(signed, out)
                changes = {Path(name): "" for name, _ in backups}
                cli.write_report(report, src, families, safety, evidence, changes, notes, detected,
                                 "apktool-selective", None, args, {"sinkholed": [], "screenshots": 0}, "base APK")
                self._register_artifact(job, out, "Cleaned APK", kind="apk")
                self._register_artifact(job, report, "Privacy Report", kind="report")
                job["summary"] = {"input_size": input_size, "output_size": out.stat().st_size, "engine": "apktool-selective"}
                return {
                    "ok": True,
                    "output": str(out),
                    "report": str(report),
                    "safety": safety,
                    "privacy_score": max(0, 100 - 4 * len(families)),
                    "notes": notes,
                    "changed_files": [str(k) for k in changes],
                }

            self._emit(job, step="Decoding & scanning", progress=45, log=f"Decoding with {args.engine} engine...")
            prepared = cli.prepare(
                args, parts[0], work, args.engine,
                apkeditor=apkeditor, recipe=loaded_recipe, notes=notes, bypass=bypass, apks=parts,
            )
            root, changes = prepared["root"], prepared["changes"]
            candidates = sorted(set(cli.sinkhole_changes(
                {}, root, extra=loaded_recipe.sinkhole_domains if loaded_recipe else None
            )))
            diff_lines = []
            for line in patcher.diff(root, changes):
                diff_lines.append(line.rstrip("\n"))
                if len(diff_lines) >= MAX_DIFF_LINES:
                    diff_lines.append("... (diff truncated for preview)")
                    break
            trackers = []
            for name in sorted(set(prepared["hits"]) | set(prepared["evidence"])):
                hit = prepared["hits"].get(name)
                trackers.append({
                    "name": name,
                    "classes": hit.classes if hit else 0,
                    "components": hit.components if hit else [],
                    "hooks": [sig for _, sig in hit.hooks] if hit else [],
                    "evidence": prepared["evidence"].get(name, []),
                })
            score = max(0, 100 - 4 * prepared["families"])
            changed_rel = [p.relative_to(root).as_posix() for p in changes]

            if mode in {"scan", "clean_preview"}:
                diff_path = job["dir"] / "preview.diff"
                diff_path.write_text("\n".join(diff_lines) + ("\n" if diff_lines else ""), encoding="utf-8")
                self._register_artifact(job, diff_path, "Unified Diff", kind="diff")
                manifest_p = None if bypass else (root / "AndroidManifest.xml")
                if manifest_p and manifest_p.is_file():
                    manifest_art = job["dir"] / "AndroidManifest.xml"
                    shutil.copy2(manifest_p, manifest_art)
                    self._register_artifact(job, manifest_art, "Decoded AndroidManifest.xml", kind="manifest")
                job["summary"] = {"privacy_score": score, "changes_count": len(changed_rel), "verdict": prepared["safety"]["verdict"]}
                return {
                    "ok": True,
                    "version": __version__,
                    "privacy_score": score,
                    "trackers": trackers,
                    "safety": prepared["safety"],
                    "detected_frameworks": detected,
                    "engine": prepared["decoded"].engine,
                    "decode_type": prepared["decoded"].decode_type,
                    "notes": notes,
                    "sinkhole": {"candidates": candidates, "endpoint": sinkhole.SINKHOLE},
                    "changed_files": changed_rel,
                    "diff_lines": diff_lines,
                    "stats": prepared["stats"],
                }

            if not changes:
                return {"ok": True, "noop": True, "notes": notes, "safety": prepared["safety"], "privacy_score": score}

            out_ext = ".apks" if bundle else ".apk"
            out = (
                Path(payload["output"]).expanduser().resolve()
                if payload.get("output")
                else job["dir"] / f"{src.stem}-cleaned{out_ext}"
            )
            if out == src.resolve():
                raise ValueError("Refusing to modify input APK in place")
            out.parent.mkdir(parents=True, exist_ok=True)
            report = out.parent / "privacy-report.md"
            backup = out.with_suffix(".backups")
            scratch_backup = work / "originals"

            self._emit(job, step="Applying & rebuilding", progress=65, log="Applying patches and rebuilding...")
            patcher.apply(root, changes, scratch_backup)
            unsigned_apk = work / "unsigned.apk"
            fallback = None
            try:
                cli.rebuild_with(args.engine, prepared["decoded"].engine, root, unsigned_apk,
                                 apkeditor=apkeditor, original=parts[0] if bypass else None)
            except engines.EngineError as error:
                if not (args.engine == "auto" and apkeditor and engines.resource_failure(str(error))):
                    raise
                fallback = str(error).splitlines()[0][:200]
                notes.append("Engine fallback: " + fallback)
                self._emit(job, log="Apktool rebuild failed on resources; retrying with APKEditor...")
                prepared = cli.prepare(
                    args, parts[0], work, "apkeditor",
                    apkeditor=apkeditor, recipe=loaded_recipe, notes=notes, bypass=bypass, apks=parts,
                )
                root, changes = prepared["root"], prepared["changes"]
                if (
                    not changes
                ):
                    return {
                        "ok": True, "noop": True, "notes": notes,
                        "safety": prepared["safety"], "privacy_score": score,
                    }
                shutil.rmtree(scratch_backup, ignore_errors=True)
                patcher.apply(root, changes, scratch_backup)
                cli.rebuild_with("apkeditor", "apkeditor", root, unsigned_apk,
                                 apkeditor=apkeditor, original=parts[0] if bypass else None)
                diff_lines = [line.rstrip("\n") for line in itertools.islice(patcher.diff(root, changes), MAX_DIFF_LINES)]

            self._emit(job, step="Aligning & signing", progress=85, log="Running zipalign -P 16 and apksigner...")
            signed = work / "signed.apk"
            creds = signing.resolve_identity(keystore=args.keystore, ks_alias=args.ks_alias, ks_pass=args.ks_pass)
            signing.sign(unsigned_apk, work, signed, creds)
            if bundle:
                signed = cli._pack_bundle(signed, parts, work, creds)
            if backup.exists():
                shutil.rmtree(backup)
            shutil.copytree(scratch_backup, backup)
            shutil.copyfile(signed, out)
            if report.exists():
                report.unlink()
            cli.write_report(
                report, src, sorted(set(prepared["hits"]) | set(prepared["evidence"])),
                prepared["safety"], prepared["evidence"], changes, notes, detected,
                prepared["decoded"].engine, fallback, args, prepared["stats"], "base APK",
            )
            diff_file = job["dir"] / "patch.diff"
            diff_file.write_text("\n".join(diff_lines) + ("\n" if diff_lines else ""), encoding="utf-8")
            if out.is_relative_to(job["dir"]):
                self._register_artifact(job, out, "Cleaned APK", kind="apk")
            if report.is_relative_to(job["dir"]):
                self._register_artifact(job, report, "Privacy Report", kind="report")
            self._register_artifact(job, diff_file, "Patch Diff", kind="diff")
            out_size = out.stat().st_size
            job["summary"] = {
                "input_size": input_size,
                "output_size": out_size,
                "privacy_score_before": score,
                "engine": prepared["decoded"].engine,
                "sinkholed": len(prepared["stats"].get("sinkholed", [])),
                "screenshots": prepared["stats"].get("screenshots", 0),
            }
            return {
                "ok": True,
                "output": str(out),
                "report": str(report),
                "engine": prepared["decoded"].engine,
                "fallback": fallback,
                "privacy_score": score,
                "safety": prepared["safety"],
                "trackers": trackers,
                "stats": prepared["stats"],
                "notes": notes,
                "changed_files": changed_rel,
            }


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
                        finished = job["status"] in {"done", "error"} and cursor >= len(job["events"])
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
                if path == "/api/jobs":
                    job = manager.submit(payload.get("type", ""), payload)
                    self._send_json(HTTPStatus.ACCEPTED, {"ok": True, "job": job})
                    return
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Not found"})
            except (ValueError, OSError, XMLSyntaxError, zipfile.BadZipFile, engines.EngineError) as error:
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(error)})

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
