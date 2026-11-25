import argparse
import json
import os
from pathlib import Path
import re
from .bundles import ABIS, select_abi, unpack
from .evidence import assess
from .verify import verify
from .rebuild import rebuild
from .signing import identity, sign
from .scanner import exodus
from .patcher import patch_smali
import shutil
import subprocess
import sys
import tempfile
import zipfile

from rich.console import Console
from rich.table import Table
from lxml.etree import XMLSyntaxError

from .llm import analyze
from .patcher import apply, diff, plan
from .scanner import RULES, parse_manifest, scan

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


def run(*args, env=None):
    subprocess.run([str(arg) for arg in args], check=True, env=env, stdout=sys.stderr)


def show(hits, family_count):
    table = Table("SDK", "Patch coverage", "Package prefix", "Manifest components", "Matched hooks")
    for rule in RULES:
        h = hits.get(rule["name"])
        if h:
            table.add_row(rule["name"], rule["coverage"], rule["prefix"], "\n".join(h.components) or "—",
                          "\n".join(sig.split("->")[1] for _,sig in h.hooks) or "—")
    console.print(table)
    console.print(f"Privacy Score: {max(0,100-4*family_count)}/100 (static SDK presence heuristic)")


def execute(args):
    if args.command == "doctor":
        for tool in TOOLS:
            console.print(tool, shutil.which(tool) or "missing")
        if shutil.which("apktool"):
            version = subprocess.check_output(["apktool","--version"],text=True).strip()
            match = re.search(r"(\d+)\.(\d+)\.(\d+)", version)
            if not match or tuple(map(int,match.groups())) < (3,0,2):
                console.print("Warning: upgrade Apktool to 3.0.2 or newer. CVE-2026-39973 affects 3.0.0 and 3.0.1.")
        console.print(INSTALL)
        return int(any(not shutil.which(t) for t in TOOLS))
    apk = args.apk.resolve(strict=True)
    with tempfile.TemporaryDirectory() as temp:
        work = Path(temp)
        root = work / "decoded"
        parts = unpack(apk,work)
        bundle = apk.suffix.lower() != ".apk"
        if args.command == "verify":
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
        bypass = getattr(args, "smali_only", False)
        if args.command == "clean":
            if args.abi and not bundle:
                raise ValueError("--abi requires a split bundle")
            parts, found = select_abi(parts, args.abi)
            if len(found) > 1 and not args.abi:
                console.print("Multiple ABIs:", ", ".join(found), "Select one with --abi for adb install-multiple.")
        if bypass:
            console.print("Smali-only mode: manifest patches and manifest scanning are skipped. Resources stay binary.")
        run("apktool", "d", *(["-r"] if bypass else []), parts[0], "-o", root)
        hits = scan(root, manifest=not bypass)
        evidence, safety = assess(root, None if bypass else parse_manifest(root / "AndroidManifest.xml"))
        external = exodus(root, args.tracker_db) if args.tracker_db else []
        families = sorted(set(hits) | set(evidence))
        if getattr(args, "json", False):
            rows = []
            for name in families:
                h = hits.get(name)
                rows.append({"name": name, "classes": h.classes if h else 0,
                             "components": h.components if h else [], "hooks": [sig for _, sig in h.hooks] if h else [],
                             "evidence": evidence.get(name, [])})
            print(json.dumps({"trackers": rows, "privacy_score": max(0, 100-4*len(families)),
                              "safety": safety, "exodus": external, "scope": "base APK"}))
        else:
            show(hits, len(families))
            for name, signals in sorted(evidence.items()):
                console.print(name, "(endpoint / SDK-key evidence):", ", ".join(signals))
            for name in external:
                console.print("Exodus match (detection only):", name)
            console.print("Patch Safety Verdict:", safety["verdict"])
            for reason in safety["reasons"]:
                console.print(reason)
        if args.command == "scan":
            return 0
        out = (args.output or apk.with_name(apk.stem+"-cleaned"+(".apks" if bundle else ".apk"))).resolve()
        report = out.parent / "privacy-report.md"
        backup = out.with_suffix(".backups")
        if out.suffix.lower() != (".apks" if bundle else ".apk") or any(p.exists() for p in (out, report, backup)):
            raise ValueError("Use a fresh output directory with an unused .apk name")
        changes = plan(root, hits, args.strip_ad_permissions, args.disable_providers, manifest=not bypass)
        # Apktool 3.0.2 emits an empty --rename-resources-package for APKs
        # with an empty resource table. Let aapt2 use the manifest package.
        metadata = root/"apktool.yml"
        if not bypass and metadata.exists():
            original = metadata.read_text(encoding="utf-8")
            fixed = re.sub(r"""(?m)^[ \t]+packageName:[ \t]*(?:''|"")?[ \t]*\n""", "", original)
            if changes and fixed != original:
                changes[metadata] = fixed
        findings = list(analyze(root, args.llm_url, args.model)) if args.ai or args.ai_patch else []
        for path, result in findings:
            console.print(json.dumps(result, ensure_ascii=True))
            if args.ai_patch and result["safe_to_noop"]:
                old = changes.get(path, path.read_text(encoding="utf-8"))
                new = patch_smali(old, {result["method_name"]})
                if old != new:
                    import difflib
                    console.print("".join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),
                        fromfile=str(path.relative_to(root)),tofile=str(path.relative_to(root)))),soft_wrap=True)
                    while True:
                        answer = input("AI proposal: [y] apply / [n] skip / [q] quit: ").strip().lower()
                        if answer in {"y","n","q"}:
                            break
                    if answer == "q":
                        return 0
                    if answer == "y":
                        changes[path] = new
        if not changes:
            console.print("No allowlisted changes. Skipping rebuild.")
            return 0
        for line in diff(root, changes):
            console.print(line.rstrip("\n"), soft_wrap=True)
        if not args.yes and input("Apply these changes and re-sign? [y/N] ").strip().lower() != "y":
            return 0
        out.parent.mkdir(parents=True, exist_ok=True)
        # Assemble in scratch first. Invalid instructions cannot reach user outputs.
        scratch_backup = work/"originals"
        apply(root, changes, scratch_backup)
        unsigned = work / "unsigned.apk"
        rebuild(root, unsigned, parts[0] if bypass else None)
        signed = work / "signed.apk"
        credentials = identity(args)
        sign(unsigned, work, signed, credentials)
        if bundle:
            packed = work/"cleaned.apks"
            with zipfile.ZipFile(packed,"w") as archive:
                archive.write(signed,"base.apk")
                for index, split in enumerate(parts[1:],1):
                    dest = work/f"signed-{index}.apk"
                    sign(split,work,dest,credentials)
                    archive.write(dest, split.name)
            signed = packed
        shutil.copytree(scratch_backup,backup)
        with out.open("xb") as dst, signed.open("rb") as src:
            shutil.copyfileobj(src, dst)
        with report.open("x", encoding="utf-8") as stream:
            stream.write("# APK Surgeon privacy report\n\nInput: "+apk.name+"\n\nDetected SDKs: "+", ".join(families)+
                "\n\nPatch Safety Verdict: "+safety["verdict"]+"\n"+"\n".join(safety["reasons"])+
                "\n\nStatic evidence:\n"+"\n".join(f"- {name}: {sig}" for name in evidence for sig in evidence[name])+
                "\n\nChanged files:\n"+"".join("- "+str(p.relative_to(root))+"\n" for p in changes)+
                "\nSignature verified. Runtime functionality and network behavior require device testing.\n")
        if bundle:
            import shlex
            console.print("Install with SAI, or in a fresh directory run:")
            console.print(f"unzip {shlex.quote(str(out))} && adb install-multiple ./*.apk")
        console.print(f"Saved {out} and {report}" )
    return 0


def main():
    parser = argparse.ArgumentParser(prog="apk-surgeon")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor")
    sub.add_parser("scan").add_argument("apk", type=Path)
    sub.add_parser("verify").add_argument("apk", type=Path)
    for command in ("scan", "verify"):
        sub.choices[command].add_argument("--json", action="store_true")
    clean = sub.add_parser("clean")
    clean.add_argument("apk", type=Path)
    clean.add_argument("-o", "--output", type=Path)
    clean.add_argument("--smali-only", action="store_true")
    clean.add_argument("--abi", choices=ABIS)
    clean.add_argument("--yes", action="store_true")
    for flag in ("strip-ad-permissions","disable-providers","ai-patch"):
        clean.add_argument("--"+flag,action="store_true")
    for flag in ("keystore","ks-alias","ks-pass"):
        clean.add_argument("--"+flag)
    for command in ("scan","clean"):
        sub.choices[command].add_argument("--tracker-db",type=Path)
    clean.add_argument("--ai", action="store_true")
    clean.add_argument("--llm-url", default="http://localhost:11434/v1")
    clean.add_argument("--model", default="qwen3:4b")
    args = parser.parse_args()
    try:
        return execute(args)
    except (OSError, EOFError, ValueError, KeyError, XMLSyntaxError, zipfile.BadZipFile, subprocess.CalledProcessError) as err:
        if getattr(args, "json", False):
            print(json.dumps({"ok": False, "error": str(err)}))
        else:
            print(f"apk-surgeon: {err}", file=sys.stderr)
        return 1
