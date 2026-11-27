"""APK Surgeon command line interface."""

import argparse
import difflib
import json
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

from lxml.etree import XMLSyntaxError
from rich.console import Console
from rich.table import Table

from . import (
    __version__,
    engines,
    frameworks,
    pipeline,
    sinkhole,
    toolkit,
)
from . import recipe as recipes
from .bundles import ABIS, unpack
from .llm import analyze
from .patcher import patch_smali
from .pipeline import (
    assess_for_selective,
    merge_bundle,
    prepare,
    rebuild_with,
    selective_clean,
    sinkhole_changes,
    write_report,
)
from .pipeline import (
    pack_bundle as _pack_bundle,
)
from .scanner import RULES
from .signing import identity, sign
from .verify import verify

__all__ = [
    "ABIS",
    "INSTALL",
    "RULES",
    "TOOLS",
    "_pack_bundle",
    "analyze",
    "assess_for_selective",
    "console",
    "identity",
    "main",
    "merge_bundle",
    "patch_smali",
    "prepare",
    "rebuild_with",
    "selective_clean",
    "sign",
    "sinkhole_changes",
    "unpack",
    "verify",
    "write_report",
]

console = Console(markup=False, highlight=False)
TOOLS = ("java", "keytool", "apktool", "apksigner", "zipalign", "aapt2")
INSTALL = """Linux (Debian/Ubuntu): sudo apt install default-jdk apktool apksigner zipalign
macOS: brew install openjdk apktool; brew install --cask android-commandlinetools
Windows: winget install EclipseAdoptium.Temurin.17.JDK
Windows Apktool: put the official wrapper (apktool.bat) and apktool.jar in a directory on PATH.
macOS/Windows Android SDK: sdkmanager "build-tools;35.0.0"; add the SDK build-tools/35.0.0 directory to PATH.
Termux: pkg install openjdk-17 apksigner; install the official Apktool JAR and Linux wrapper in $PREFIX/bin.
Termux: if zipalign is unavailable in your repositories, use scan locally and clean on desktop.
Apktool installation: https://apktool.org/docs/install/
Use maintained tools. On Windows, run from PowerShell or cmd with the Android tools on PATH."""


def run(*args):
    argv = [str(arg) for arg in args]
    if argv:
        argv[0] = engines.resolve_executable(argv[0])
    subprocess.run(argv, check=True, stdout=sys.stderr)


def show(hits, family_count):
    table = Table("SDK", "Patch coverage", "Package prefix", "Manifest components", "Matched hooks")
    for rule in RULES:
        hit = hits.get(rule["name"])
        if hit:
            table.add_row(
                rule["name"], rule["coverage"], rule["prefix"], "\n".join(hit.components) or "-",
                "\n".join(sig.split("->")[1] for _, sig in hit.hooks) or "-",
            )
    for name in sorted(hits):
        if name.startswith("Recipe:") and hits[name].classes:
            table.add_row(name, "exact-method", "-", "-", str(hits[name].classes) + " class(es)")
    console.print(table)
    console.print(f"Privacy Score: {max(0, 100-4*family_count)}/100 (static SDK presence heuristic)")


def doctor(args):
    for tool in TOOLS:
        console.print(tool, shutil.which(tool) or "missing")
    apktool_bin = shutil.which("apktool")
    if apktool_bin:
        try:
            version = subprocess.check_output(
                [apktool_bin, "--version"], stderr=subprocess.STDOUT, text=True, timeout=15
            ).strip()
        except (OSError, subprocess.SubprocessError) as error:
            console.print(f"Warning: apktool health check failed: {error}")
        else:
            match = re.search(r"(\d+)\.(\d+)\.(\d+)", version)
            if not match or tuple(map(int, match.groups())) < (3, 0, 3):
                console.print("Warning: upgrade Apktool to 3.0.3 or newer. CVE-2026-39973 affects 3.0.0 and 3.0.1.")
    try:
        target = engines.resolve_apkeditor(args.apkeditor_jar)
    except engines.EngineError as error:
        console.print(str(error))
        target = None
    console.print(engines.doctor_note(target))
    console.print(INSTALL)
    return int(any(not shutil.which(tool) for tool in TOOLS))


def _print_inspect(res):
    console.print("File:", res["file"], f"({res['file_size']} bytes, {res['archive_type']})")
    console.print("ABIs:", ", ".join(res["abis"]) or "none")
    console.print("Frameworks:", ", ".join(res["detected_frameworks"]) or "none")
    console.print("Pairip:", "BLOCKED" if res["pairip"]["blocked"] else "none detected")
    for reason in res["pairip"]["reasons"]:
        console.print("-", reason)
    arsc = res["resources_arsc"]
    arsc_status = arsc["compress_type"] if arsc["present"] else "absent"
    console.print("resources.arsc:", arsc_status)
    console.print("extractNativeLibs:", res["extract_native_libs"] if res["extract_native_libs"] is not None else "unset")
    console.print("Native libs:", res["native_libs"]["count"], f"(all stored: {res['native_libs']['all_stored']})")
    if res["split_apks"]:
        console.print("Split APKs:", ", ".join(res["split_apks"]))
    for entry in res["dex_files"]:
        if entry["version"] is not None:
            sections = f", {entry['container_sections']} container section(s)" if entry["container_sections"] > 1 else ""
            console.print("DEX:", entry["name"], f"version 0{entry['version']}{sections}")
        else:
            console.print("DEX:", entry["name"], "unreadable:", entry.get("error", "unknown"))
    if res["badging"]:
        b = res["badging"]
        console.print(
            "Package:", b.get("package") or "-",
            "versionCode:", b.get("version_code") or "-",
            "minSdk:", b.get("min_sdk") or "-",
            "targetSdk:", b.get("target_sdk") or "-",
        )
        if b.get("application_label"):
            console.print("Label:", b["application_label"])


def _execute_toolkit(args):
    if args.command == "decode":
        out = args.output or args.apk.with_name(args.apk.stem + "-decoded")
        res = toolkit.decode_apk(
            args.apk, out, engine=args.engine, apkeditor_jar=args.apkeditor_jar,
            no_res=args.no_res, no_src=args.no_src, force=args.force,
        )
        if args.json:
            print(json.dumps(res))
        else:
            console.print(
                f"Decoded {args.apk.name} -> {res['output']} "
                f"(engine: {res['engine']}, decode: {res['decode_type'] or 'default'})"
            )
            for line in res["notes"]:
                console.print(line)
        return 0
    if args.command == "build":
        out = args.output or args.directory.with_suffix(".apk")
        res = toolkit.build_apk(
            args.directory, out, engine=args.engine, apkeditor_jar=args.apkeditor_jar,
            unsigned=args.unsigned, force=args.force,
            keystore=args.keystore, ks_alias=args.ks_alias, ks_pass=args.ks_pass,
        )
        if args.json:
            print(json.dumps(res))
        else:
            status = "signed & verified" if res["signed"] else "unsigned & aligned"
            console.print(f"Built {res['output']} (engine: {res['engine']}, {status})")
        return 0 if res["ok"] else 1
    if args.command == "merge":
        out = args.output or args.apk.with_name(args.apk.stem + "-merged.apk")
        res = toolkit.merge_bundle(
            args.apk, out, abi=args.abi, apkeditor_jar=args.apkeditor_jar,
            unsigned=args.unsigned, force=args.force,
            keystore=args.keystore, ks_alias=args.ks_alias, ks_pass=args.ks_pass,
        )
        if args.json:
            print(json.dumps(res))
        else:
            console.print(
                f"Merged {args.apk.name} -> {res['output']} "
                f"(ABIs: {', '.join(res['abis']) or 'none'}, signed: {res['signed']})"
            )
            for warning in res["warnings"]:
                console.print("Warning:", warning)
            for line in res["notes"]:
                console.print(line)
        return 0 if res["ok"] else 1
    if args.command == "sign":
        out = args.output or args.apk.with_name(args.apk.stem + "-signed.apk")
        res = toolkit.sign_apk(
            args.apk, out, force=args.force,
            keystore=args.keystore, ks_alias=args.ks_alias, ks_pass=args.ks_pass,
        )
        if args.json:
            print(json.dumps(res))
        else:
            certs = res["verify"]["apks"][0]["certificates_sha256"] if res["verify"] else []
            console.print(f"Signed {res['output']} (16 KiB aligned, verified)")
            if certs:
                console.print("Signer SHA-256:", ", ".join(certs))
        return 0 if res["ok"] else 1
    res = toolkit.inspect_apk(args.apk)
    if args.json:
        print(json.dumps(res))
    else:
        _print_inspect(res)
    return 0


def execute(args):
    if args.command == "doctor":
        return doctor(args)
    if args.command == "ui":
        from . import ui

        return ui.serve(host=args.host, port=args.port, open_browser=not args.no_browser)
    if args.command in {"decode", "build", "merge", "sign", "inspect"}:
        return _execute_toolkit(args)

    apk = args.apk.resolve(strict=True)
    allow_custom = getattr(args, "allow_custom_domains", False)
    loaded_recipe = (
        recipes.load(args.recipe, allow_custom_domains=allow_custom)
        if getattr(args, "recipe", None)
        else None
    )
    notes = []
    if allow_custom:
        custom = loaded_recipe.custom_sinkhole_domains if loaded_recipe else []
        custom_note = (
            "Warning: --allow-custom-domains enabled custom sinkhole domains: " + ", ".join(custom)
            if custom
            else "Warning: --allow-custom-domains enabled; non-allowlisted recipe domains are permitted."
        )
        if not getattr(args, "json", False):
            console.print(custom_note)
        notes.append(custom_note)
    if args.command == "verify":
        import tempfile

        with tempfile.TemporaryDirectory() as temp:
            parts = unpack(apk, Path(temp))
            result = verify(parts)
        if args.json:
            print(json.dumps(result))
        else:
            for row in result["apks"]:
                console.print(row["apk"], "alignment:", row["aligned"], "signature schemes:", row["schemes"])
                console.print("Signer SHA-256:", ", ".join(row["certificates_sha256"]) or "unavailable")
                for error in row["errors"]:
                    console.print(error)
            console.print("PASS" if result["ok"] else "FAIL")
        return int(not result["ok"])

    def _on_event(*, step=None, progress=None, log=None):
        if log and not getattr(args, "json", False):
            console.print(log)

    def _on_scan_ready(prepared, detected, candidates, external, scan_notes):
        if getattr(args, "json", False):
            rows = []
            for name in sorted(set(prepared["hits"]) | set(prepared["evidence"])):
                hit = prepared["hits"].get(name)
                rows.append({
                    "name": name, "classes": hit.classes if hit else 0,
                    "components": hit.components if hit else [],
                    "hooks": [sig for _, sig in hit.hooks] if hit else [],
                    "evidence": prepared["evidence"].get(name, []),
                })
            print(json.dumps({
                "version": __version__, "trackers": rows,
                "privacy_score": max(0, 100 - 4 * prepared["families"]),
                "safety": prepared["safety"], "exodus": external, "scope": "base APK",
                "detected_frameworks": detected, "engine": prepared["decoded"].engine,
                "decode_type": prepared["decoded"].decode_type, "notes": scan_notes,
                "sinkhole": {"candidates": candidates, "endpoint": sinkhole.SINKHOLE},
            }))
            return
        show(prepared["hits"], prepared["families"])
        if detected:
            console.print("Detected native frameworks:", ", ".join(detected))
            console.print("Score caveat:", frameworks.FRAMEWORK_CAVEAT)
        for name, signals in sorted(prepared["evidence"].items()):
            console.print(name, "(endpoint / SDK-key evidence):", ", ".join(signals))
        for name in prepared["hits"]:
            if name.startswith("Recipe:"):
                console.print("Recipe match:", name)
        for name in external:
            console.print("Exodus match (detection only):", name)
        console.print("Patch Safety Verdict:", prepared["safety"]["verdict"])
        for reason in prepared["safety"]["reasons"]:
            console.print(reason)
        for line in scan_notes:
            console.print(line)
        console.print("Engine:", prepared["decoded"].engine, "decode:", prepared["decoded"].decode_type or "default")
        if candidates:
            console.print("Sinkholeable telemetry URLs:", len(candidates))
            for value in candidates:
                console.print("-", value, "->", sinkhole.SINKHOLE)

    def _ai_review(root, changes):
        findings = list(analyze(root, args.llm_url, args.model))
        for path, model_result in findings:
            console.print(json.dumps(model_result, ensure_ascii=True))
            if args.ai_patch and model_result["safe_to_noop"]:
                old = changes.get(path, path.read_text(encoding="utf-8"))
                new = patch_smali(old, {model_result["method_name"]})
                if old != new:
                    console.print("".join(difflib.unified_diff(
                        old.splitlines(True), new.splitlines(True),
                        fromfile=str(path.relative_to(root)), tofile=str(path.relative_to(root)),
                    )), soft_wrap=True)
                    while True:
                        answer = input("AI proposal: [y] apply / [n] skip / [q] quit: ").strip().lower()
                        if answer in {"y", "n", "q"}:
                            break
                    if answer == "q":
                        return False
                    if answer == "y":
                        changes[path] = new
        return True

    def _confirm(lines):
        for line in lines:
            console.print(line.rstrip("\n"), soft_wrap=True)
        return bool(args.yes or input("Apply these changes and re-sign? [y/N] ").strip().lower() == "y")

    bundle_in = apk.suffix.lower() != ".apk"
    default_out = apk.with_name(
        apk.stem + "-cleaned" + (".apks" if bundle_in and not getattr(args, "merge_splits", False) else ".apk")
    )
    res = pipeline.run_scan_or_clean(
        args,
        apk,
        mode=args.command,
        loaded_recipe=loaded_recipe,
        notes=notes,
        default_output=default_out,
        overwrite_existing=False,
        on_event=_on_event,
        on_scan_ready=_on_scan_ready if args.command == "scan" or not getattr(args, "json", False) else None,
        ai_review_cb=_ai_review,
        confirm_cb=_confirm,
        ops=sys.modules[__name__],
    )
    if res.get("noop"):
        console.print("No allowlisted changes. Skipping rebuild.")
        return 0
    if res.get("aborted") or args.command == "scan":
        return 0
    if res.get("bundle"):
        import shlex
        console.print("Install with SAI, or in a fresh directory run:", soft_wrap=True)
        console.print(f"unzip {shlex.quote(res['output'])} && adb install-multiple ./*.apk")
    console.print(f"Saved {res['output']} and {res['report']}")
    return 0


def _add_signing_flags(parser):
    for flag in ("keystore", "ks-alias", "ks-pass"):
        parser.add_argument("--" + flag)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="apk-surgeon")
    parser.add_argument("--version", action="version", version=f"apk-surgeon {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor").add_argument("--apkeditor-jar", type=Path)
    for command in ("scan", "verify", "clean"):
        sub.add_parser(command).add_argument("apk", type=Path)
    for command in ("scan", "verify"):
        sub.choices[command].add_argument("--json", action="store_true")
    for command in ("scan", "clean"):
        sub.choices[command].add_argument("--tracker-db", type=Path)
        sub.choices[command].add_argument("--engine", choices=("auto", "apktool", "apkeditor"), default="auto")
        sub.choices[command].add_argument("--apkeditor-jar", type=Path)
        sub.choices[command].add_argument("--recipe", type=Path)
        sub.choices[command].add_argument("--allow-custom-domains", action="store_true")
    clean = sub.choices["clean"]
    clean.add_argument("-o", "--output", type=Path)
    clean.add_argument("--smali-only", action="store_true")
    clean.add_argument("--abi", choices=ABIS)
    clean.add_argument("--yes", action="store_true")
    for flag in ("strip-ad-permissions", "disable-providers", "ai-patch"):
        clean.add_argument("--" + flag, action="store_true")
    _add_signing_flags(clean)
    clean.add_argument("--ai", action="store_true")
    clean.add_argument("--llm-url", default="http://localhost:11434/v1")
    clean.add_argument("--model", default="qwen3:4b")
    for flag in ("merge-splits", "selective-dex", "sinkhole", "trust-user-ca",
                 "allow-screenshots", "force-unsafe"):
        clean.add_argument("--" + flag, action="store_true")

    decode_p = sub.add_parser("decode")
    decode_p.add_argument("apk", type=Path)
    decode_p.add_argument("-o", "--output", type=Path)
    decode_p.add_argument("--engine", choices=("auto", "apktool", "apkeditor"), default="auto")
    decode_p.add_argument("--apkeditor-jar", type=Path)
    decode_p.add_argument("-r", "--no-res", action="store_true")
    decode_p.add_argument("-s", "--no-src", action="store_true")
    decode_p.add_argument("--force", action="store_true")
    decode_p.add_argument("--json", action="store_true")

    build_p = sub.add_parser("build")
    build_p.add_argument("directory", type=Path)
    build_p.add_argument("-o", "--output", type=Path)
    build_p.add_argument("--engine", choices=("auto", "apktool", "apkeditor"), default="auto")
    build_p.add_argument("--apkeditor-jar", type=Path)
    build_p.add_argument("--unsigned", action="store_true")
    build_p.add_argument("--force", action="store_true")
    _add_signing_flags(build_p)
    build_p.add_argument("--json", action="store_true")

    merge_p = sub.add_parser("merge")
    merge_p.add_argument("apk", type=Path)
    merge_p.add_argument("-o", "--output", type=Path)
    merge_p.add_argument("--abi", choices=ABIS)
    merge_p.add_argument("--apkeditor-jar", type=Path)
    merge_p.add_argument("--unsigned", action="store_true")
    merge_p.add_argument("--force", action="store_true")
    _add_signing_flags(merge_p)
    merge_p.add_argument("--json", action="store_true")

    sign_p = sub.add_parser("sign")
    sign_p.add_argument("apk", type=Path)
    sign_p.add_argument("-o", "--output", type=Path)
    sign_p.add_argument("--force", action="store_true")
    _add_signing_flags(sign_p)
    sign_p.add_argument("--json", action="store_true")

    inspect_p = sub.add_parser("inspect")
    inspect_p.add_argument("apk", type=Path)
    inspect_p.add_argument("--json", action="store_true")

    ui_p = sub.add_parser("ui")
    ui_p.add_argument("--host", default="127.0.0.1")
    ui_p.add_argument("--port", type=int, default=8765)
    ui_p.add_argument("--no-browser", action="store_true")
    args = parser.parse_args(argv)
    try:
        return execute(args)
    except (OSError, EOFError, ValueError, KeyError, XMLSyntaxError, zipfile.BadZipFile,
            subprocess.CalledProcessError, engines.EngineError) as err:
        if getattr(args, "json", False):
            print(json.dumps({"ok": False, "error": str(err)}))
        else:
            print(f"apk-surgeon: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
