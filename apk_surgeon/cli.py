import argparse
import json
import os
from pathlib import Path
import secrets
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
from .scanner import RULES, scan

console = Console(markup=False, highlight=False)
TOOLS = ("java", "keytool", "apktool", "apksigner", "zipalign")
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
    subprocess.run([str(arg) for arg in args], check=True, env=env)


def show(hits):
    table = Table("SDK", "Package prefix", "Manifest components", "Matched hooks")
    for rule in RULES:
        h = hits.get(rule["name"])
        if h:
            table.add_row(rule["name"], rule["prefix"], "\n".join(h.components) or "—",
                          "\n".join(sig.split("->")[1] for _,sig in h.hooks) or "—")
    console.print(table)
    console.print(f"Privacy Score: {max(0,100-4*len(hits))}/100 (static SDK presence heuristic)")


def sign(unsigned, work, signed):
    aligned = work / "aligned.apk"
    run("zipalign", "-P", "16", "-f", "4", unsigned, aligned)
    key = os.getenv("APK_SURGEON_KEYSTORE")
    env = os.environ.copy()
    alias = env.get("APK_SURGEON_ALIAS", "surgeon")
    if not key:
        key = work / "local.p12"
        env["APK_SURGEON_PASSWORD"] = secrets.token_urlsafe(32)
        run("keytool", "-genkeypair", "-storetype", "PKCS12", "-keystore", key, "-storepass:env",
            "APK_SURGEON_PASSWORD", "-alias", alias, "-keyalg", "RSA", "-keysize", "3072",
            "-validity", "3650", "-dname", "CN=APK Surgeon Local", env=env)
    elif not env.get("APK_SURGEON_PASSWORD"):
        raise ValueError("Set APK_SURGEON_PASSWORD for the supplied keystore")
    run("apksigner", "sign", "--ks", key, "--ks-key-alias", alias, "--ks-pass",
        "env:APK_SURGEON_PASSWORD", "--out", signed, aligned, env=env)
    run("apksigner", "verify", "--verbose", signed)


def execute(args):
    if args.command == "doctor":
        for tool in TOOLS:
            console.print(tool, shutil.which(tool) or "missing")
        console.print(INSTALL)
        return int(any(not shutil.which(t) for t in TOOLS))
    apk = args.apk.resolve(strict=True)
    with zipfile.ZipFile(apk) as archive:
        if "AndroidManifest.xml" not in archive.namelist():
            raise ValueError("Expected a standalone APK with AndroidManifest.xml")
    with tempfile.TemporaryDirectory() as temp:
        work = Path(temp)
        root = work / "decoded"
        run("apktool", "d", apk, "-o", root)
        hits = scan(root)
        show(hits)
        if args.command == "scan":
            return 0
        out = (args.output or apk.with_name(apk.stem+"-clean.apk")).resolve()
        report = out.parent / "privacy-report.md"
        backup = out.with_suffix(".backups")
        if out.suffix.lower() != ".apk" or any(p.exists() for p in (out, report, backup)):
            raise ValueError("Use a fresh output directory with an unused .apk name")
        changes = plan(root, hits)
        findings = list(analyze(root, args.llm_url, args.model)) if args.ai else []
        for result in findings:
            console.print(json.dumps(result, ensure_ascii=True))
        if not changes:
            console.print("No allowlisted changes. Skipping rebuild.")
            return 0
        for line in diff(root, changes):
            console.print(line.rstrip("\n"), soft_wrap=True)
        if not args.yes and input("Apply these changes and re-sign? [y/N] ").strip().lower() != "y":
            return 0
        out.parent.mkdir(parents=True, exist_ok=True)
        backup.mkdir()
        apply(root, changes, backup)
        unsigned = work / "unsigned.apk"
        run("apktool", "b", root, "-o", unsigned)
        signed = work / "signed.apk"
        sign(unsigned, work, signed)
        with out.open("xb") as dst, signed.open("rb") as src:
            shutil.copyfileobj(src, dst)
        with report.open("x", encoding="utf-8") as stream:
            stream.write("# APK Surgeon privacy report\n\nInput: "+apk.name+"\n\nDetected SDKs: "+", ".join(hits)+
                "\n\nChanged files:\n"+"".join("- "+str(p.relative_to(root))+"\n" for p in changes)+
                "\nSignature verified. Runtime functionality and network behavior require device testing.\n")
        console.print(f"Saved {out} and {report}" )
    return 0


def main():
    parser = argparse.ArgumentParser(prog="apk-surgeon")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor")
    sub.add_parser("scan").add_argument("apk", type=Path)
    clean = sub.add_parser("clean")
    clean.add_argument("apk", type=Path)
    clean.add_argument("-o", "--output", type=Path)
    clean.add_argument("--yes", action="store_true")
    clean.add_argument("--ai", action="store_true")
    clean.add_argument("--llm-url", default="http://localhost:11434/v1")
    clean.add_argument("--model", default="qwen3:4b")
    try:
        return execute(parser.parse_args())
    except (OSError, EOFError, ValueError, KeyError, XMLSyntaxError, zipfile.BadZipFile, subprocess.CalledProcessError) as err:
        print(f"apk-surgeon: {err}", file=sys.stderr)
        return 1
