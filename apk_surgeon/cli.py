"""APK Surgeon command line interface."""

import argparse
import difflib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from lxml.etree import XMLSyntaxError
from rich.console import Console
from rich.table import Table

from . import __version__, audit, dex_scanner, engines, frameworks, layout, rebuild, selective, sinkhole
from . import recipe as recipes
from .bundles import ABIS, select_abi, unpack
from .evidence import assess
from .llm import analyze
from .patcher import apply, diff, patch_smali, plan
from .scanner import RULES, exodus, parse_manifest, scan
from .signing import identity, sign
from .verify import verify

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
    subprocess.run([str(arg) for arg in args], check=True, stdout=sys.stderr)


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
    if shutil.which("apktool"):
        version = subprocess.check_output(["apktool", "--version"], text=True).strip()
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


def decoder(engine, apk, root, *, no_res, apkeditor, notes):
    """Decode with the requested engine, honouring auto-fallback."""
    if engine == "apkeditor":
        if not apkeditor:
            raise ValueError(
                "--engine apkeditor needs APKEditor. Pass --apkeditor-jar PATH, set "
                f"APK_SURGEON_APKEDITOR_JAR, or download {engines.DOWNLOAD}"
            )
        result = engines.decode_apkeditor(apkeditor, apk, root)
        notes.extend(result.notes)
        return result
    if engine == "apktool" or not apkeditor:
        return engines.decode_apktool(apk, root, no_res=no_res)
    try:
        return engines.decode_apktool(apk, root, no_res=no_res)
    except engines.EngineError as error:
        notes.append("Apktool decode failed; fell back to APKEditor. " + str(error).splitlines()[0][:200])
        result = engines.decode_apkeditor(apkeditor, apk, root)
        notes.extend(result.notes)
        return result


def _edit(changes, path, transform):
    """Apply a text transform on top of any planned change for ``path``."""
    text = changes.get(path)
    if text is None:
        text = path.read_text(encoding="utf-8")
    edited, found = transform(text)
    if edited != text:
        changes[path] = edited
    return found


def sinkhole_changes(changes, root, *, dexes=None):
    """Rewrite allowlisted telemetry URLs, optionally limited to matched DEX files."""
    found = []
    for path in layout.smali_files(root, dexes):
        rewrites = _edit(changes, path, sinkhole.rewrite)
        found.extend(value for value, _ in rewrites)
    return found


def hooks_by_descriptor(recipe=None):
    """Map smali class descriptors to the exact hook signatures to patch."""
    mapping = {}
    for rule in RULES:
        for hook in rule["hooks"]:
            descriptor, signature = hook.split("->", 1)
            mapping.setdefault(descriptor, set()).add(signature)
    if recipe:
        for descriptor, signatures in recipe.methods.items():
            mapping.setdefault(descriptor, set()).update(signatures)
    return mapping


def needs(body, descriptors):
    for descriptor in descriptors:
        if descriptor in body:
            return True
    return False


def prepare(args, apk, work, engine, *, apkeditor, recipe, notes, bypass, apks=None):
    """Decode, scan, plan and stage changes for one engine attempt."""
    root = work / f"decoded-{engine}"
    decoded = decoder(engine, apk, root, no_res=bypass, apkeditor=apkeditor, notes=notes)
    root = decoded.root
    manifest = None if bypass else layout.manifest(root)
    hits = scan(root, manifest=manifest is not None, recipe=recipe)
    tree = parse_manifest(manifest) if manifest is not None else None
    evidence, safety = assess(root, tree, apks=apks if apks is not None else [apk], recipe=recipe)
    family_count = len(sorted(set(hits) | set(evidence)))
    changes = plan(
        root, hits, getattr(args, "strip_ad_permissions", False),
        getattr(args, "disable_providers", False),
        manifest=manifest is not None, recipe=recipe,
    )
    stats = {"sinkholed": [], "screenshots": 0}
    if getattr(args, "sinkhole", False):
        try:
            matched = selective.dex_candidates(apk, sinkhole_hosts(recipe))
        except selective.SelectiveError:
            matched = []
        dexes = {int(name[7:-4] or 1) for name in matched} if matched else None
        stats["sinkholed"] = sinkhole_changes(changes, root, dexes=dexes)
    if getattr(args, "allow_screenshots", False):
        total = 0
        for path in layout.smali_files(root):
            text = changes[path] if path in changes else path.read_text(encoding="utf-8")
            if "0x2000" in text:
                total += _edit(changes, path, audit.allow_screenshots_text)
        stats["screenshots"] = total
    if getattr(args, "trust_user_ca", False) and not bypass:
        if decoded.decode_type not in (None, "xml"):
            raise ValueError(
                "--trust-user-ca needs editable XML resources, but APKEditor decoded them as "
                f"{decoded.decode_type}. Use --engine apktool or a non-obfuscated APK."
            )
        manifest_path = layout.manifest(root)
        audit_changes, _ = audit.trust_user_ca(root, manifest_text=changes.get(manifest_path))
        changes.update(audit_changes)
    metadata = root / "apktool.yml"
    if not bypass and metadata.exists():
        original = metadata.read_text(encoding="utf-8")
        fixed = re.sub(r"""(?m)^[ \t]+packageName:[ \t]*(?:''|"")?[ \t]*\n""", "", original)
        if changes and fixed != original:
            changes[metadata] = fixed
    return {"decoded": decoded, "root": root, "hits": hits, "evidence": evidence, "safety": safety,
            "families": family_count, "changes": changes, "stats": stats}


def sinkhole_hosts(recipe=None):
    hosts = set(sinkhole.ALLOWLIST)
    if recipe:
        hosts.update(recipe.sinkhole_domains)
    return sorted(hosts)


def selective_transform(args, recipe):
    """Build the per-file transform used by the selective DEX path."""
    mapping = hooks_by_descriptor(recipe)

    def transform(path, text):
        found = []
        match = re.search(r"(?m)^\.class[^\n]*?\s(L[^;\s]+;)", text)
        if match and match.group(1) in mapping:
            edited = patch_smali(text, mapping[match.group(1)])
            if edited != text:
                text = edited
                found.append("method " + match.group(1))
        if getattr(args, "sinkhole", False):
            text, rewrites = sinkhole.rewrite(text)
            found.extend(value for value, _ in rewrites)
        if getattr(args, "allow_screenshots", False) and "0x2000" in text:
            text, count = audit.allow_screenshots_text(text)
            found.extend("FLAG_SECURE" for _ in range(count))
        return text, found

    return transform


def selective_clean(args, apk, work, recipe, notes):
    """Patch only matched DEX files and splice them back.  None means fall back."""
    with zipfile.ZipFile(apk) as archive:
        dexes = dex_scanner.dex_entries(archive)
        for name in dexes:
            try:
                if dex_scanner.parse_header(dex_scanner._read_dex(archive, name)).version >= 41:
                    notes.append(f"{name} uses DEX 041 container format; using a full decode.")
                    return None
            except dex_scanner.DexError:
                pass
    if len(dexes) < 2:
        return None
    needles = [rule["prefix"].replace(".", "/") for rule in RULES]
    needles += [descriptor[1:-1] for descriptor in hooks_by_descriptor(recipe)]
    if args.sinkhole:
        needles += sinkhole_hosts(recipe)
    try:
        candidates = selective.dex_candidates(apk, needles)
    except selective.SelectiveError as error:
        notes.append(f"Selective DEX scan failed ({error}); using a full decode.")
        return None
    if not candidates or set(candidates) == set(dexes):
        notes.append("Every DEX file matches; using a full decode.")
        return None
    notes.append(
        "Selective DEX mode: patching " + ", ".join(candidates) + " and copying all other entries byte for byte."
    )
    working = apk
    backups = []
    transform = selective_transform(args, recipe)
    for index, name in enumerate(candidates):
        try:
            working, changed, found = selective.patch_dex(working, work / f"selective-{index}", name, transform)
        except (engines.EngineError, selective.SelectiveError) as error:
            notes.append(f"Selective patch of {name} failed ({error}); using a full decode.")
            return None
        if changed:
            backups.append((name, changed))
    return working, backups


def _pack_bundle(signed_base, parts, work, credentials):
    packed = work / "cleaned.apks"
    with zipfile.ZipFile(packed, "w") as archive:
        archive.write(signed_base, "base.apk")
        for index, split in enumerate(parts[1:], 1):
            dest = work / f"signed-{index}.apk"
            sign(split, work, dest, credentials)
            archive.write(dest, split.name)
    return packed


def merge_bundle(args, parts, work, apkeditor):
    if not apkeditor:
        raise ValueError(
            "--merge-splits needs APKEditor. Pass --apkeditor-jar PATH, set APK_SURGEON_APKEDITOR_JAR, "
            f"or download {engines.DOWNLOAD}"
        )
    directory = work / "splits"
    directory.mkdir()
    for part in parts:
        shutil.copy2(part, directory / part.name)
    merged = work / "merged.apk"
    engines.merge_splits(apkeditor, directory, merged)
    return merged


def execute(args):
    if args.command == "doctor":
        return doctor(args)

    apk = args.apk.resolve(strict=True)
    recipe = recipes.load(args.recipe) if getattr(args, "recipe", None) else None
    with tempfile.TemporaryDirectory() as temp:
        work = Path(temp)
        parts = unpack(apk, work)
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

        apkeditor = engines.resolve_apkeditor(getattr(args, "apkeditor_jar", None))
        bypass = getattr(args, "smali_only", False)
        if args.command == "clean" and args.abi and not bundle:
            raise ValueError("--abi requires a split bundle")
        if args.command == "clean" and args.merge_splits and not bundle:
            raise ValueError("--merge-splits requires a .xapk, .apkm or .apks bundle")
        if args.command == "clean" and args.merge_splits:
            parts, _ = select_abi(parts, args.abi)
            built = merge_bundle(args, parts, work, apkeditor)
            console.print("Merged splits into one standalone APK with APKEditor.")
            parts, bundle = [built], False
            apk = built
        elif args.command == "clean" and bundle:
            parts, found = select_abi(parts, args.abi)
            if len(found) > 1 and not args.abi:
                console.print("Multiple ABIs:", ", ".join(found), "Select one with --abi for adb install-multiple.")
        if bypass:
            console.print("Smali-only mode: manifest patches and manifest scanning are skipped. Resources stay binary.")

        detected = frameworks.detect(parts)
        blocked, blocked_reasons = frameworks.pairip_detected(parts)
        notes = []
        if blocked:
            console.print("BLOCKED (Pairip VM): Google Play Automatic Protection is present.")
            for reason in blocked_reasons:
                console.print("-", reason)
            if args.command == "clean" and not args.force_unsafe:
                raise ValueError(
                    "Refusing to patch a Pairip-protected APK. Static re-signing cannot defeat the Pairip VM and "
                    "usually produces a non-launching app. Use a local VPN firewall such as RethinkDNS or "
                    "TrackerControl instead, or pass --force-unsafe to override at your own risk."
                )
            if args.command == "clean":
                notes.append("Pairip BLOCKED overridden with --force-unsafe.")

        output = None
        if args.command == "clean":
            out = (args.output or apk.with_name(apk.stem + "-cleaned" + (".apks" if bundle else ".apk"))).resolve()
            report = out.parent / "privacy-report.md"
            backup = out.with_suffix(".backups")
            if out.suffix.lower() != (".apks" if bundle else ".apk") or any(
                path.exists() for path in (out, report, backup)
            ):
                raise ValueError("Use a fresh output directory with an unused .apk name")
            output = (out, report, backup)

        if args.command == "clean" and bypass and args.trust_user_ca:
            console.print("Warning: --trust-user-ca cannot edit the manifest in --smali-only mode. Flag ignored.")

        if args.command == "clean" and args.selective_dex and (
                args.strip_ad_permissions or args.disable_providers or args.trust_user_ca
                or (recipe and recipe.disable_components)):
            raise ValueError(
                "--selective-dex patches DEX files only and cannot edit the manifest. Drop it, or drop "
                "--strip-ad-permissions/--disable-providers/--trust-user-ca/manifest recipe components."
            )
        selective_result = None
        if args.command == "clean" and (args.selective_dex or (bypass and not args.trust_user_ca)):
            selective_result = selective_clean(args, parts[0], work, recipe, notes)

        if selective_result:
            staged, backups = selective_result
            evidence, safety = assess_for_selective(staged, parts[1:], recipe)
            families = sorted(evidence)
            for line in notes:
                console.print(line)
            changes = {Path(name): "" for name, _ in backups}
            for line in dict.fromkeys(line for _, files in backups for line in files):
                console.print("patched", line)
            if not backups:
                console.print("No allowlisted changes. Skipping rebuild.")
                return 0
            if not args.yes and input("Apply these changes and re-sign? [y/N] ").strip().lower() != "y":
                return 0
            out, report, backup = output
            out.parent.mkdir(parents=True, exist_ok=True)
            backup.mkdir()
            with zipfile.ZipFile(parts[0]) as archive:
                for name, _ in backups:
                    (backup / (name + ".bak")).write_bytes(archive.read(name))
            signed = work / "signed.apk"
            credentials = identity(args)
            sign(staged, work, signed, credentials)
            if bundle:
                signed = _pack_bundle(signed, parts, work, credentials)
            shutil.copyfile(signed, out)
            write_report(report, apk, families, safety, evidence, changes, notes, detected,
                         "apktool-selective", None, args, {"sinkholed": [], "screenshots": 0}, "base APK")
            console.print(f"Saved {out} and {report}")
            return 0

        result = prepare(args, parts[0], work, args.engine, apkeditor=apkeditor, recipe=recipe,
                         notes=notes, bypass=bypass, apks=parts)
        root, changes = result["root"], result["changes"]
        candidates = sorted(set(sinkhole_changes({}, root)))
        external = exodus(root, args.tracker_db) if getattr(args, "tracker_db", None) else []
        if getattr(args, "json", False):
            rows = []
            for name in sorted(set(result["hits"]) | set(result["evidence"])):
                hit = result["hits"].get(name)
                rows.append({
                    "name": name, "classes": hit.classes if hit else 0,
                    "components": hit.components if hit else [],
                    "hooks": [sig for _, sig in hit.hooks] if hit else [],
                    "evidence": result["evidence"].get(name, []),
                })
            print(json.dumps({
                "version": __version__, "trackers": rows,
                "privacy_score": max(0, 100 - 4 * result["families"]),
                "safety": result["safety"], "exodus": external, "scope": "base APK",
                "detected_frameworks": detected, "engine": result["decoded"].engine,
                "decode_type": result["decoded"].decode_type, "notes": notes,
                "sinkhole": {"candidates": candidates, "endpoint": sinkhole.SINKHOLE},
            }))
        else:
            show(result["hits"], result["families"])
            if detected:
                console.print("Detected native frameworks:", ", ".join(detected))
                console.print("Score caveat:", frameworks.FRAMEWORK_CAVEAT)
            for name, signals in sorted(result["evidence"].items()):
                console.print(name, "(endpoint / SDK-key evidence):", ", ".join(signals))
            for name in result["hits"]:
                if name.startswith("Recipe:"):
                    console.print("Recipe match:", name)
            for name in external:
                console.print("Exodus match (detection only):", name)
            console.print("Patch Safety Verdict:", result["safety"]["verdict"])
            for reason in result["safety"]["reasons"]:
                console.print(reason)
            for line in notes:
                console.print(line)
            console.print("Engine:", result["decoded"].engine, "decode:", result["decoded"].decode_type or "default")
            if candidates:
                console.print("Sinkholeable telemetry URLs:", len(candidates))
                for value in candidates:
                    console.print("-", value, "->", sinkhole.SINKHOLE)
        if args.command == "scan":
            return 0
        if external:
            result["evidence"].setdefault("Exodus", []).extend(external)

        out, report, backup = output
        findings = [] if selective_result else list(
            analyze(root, args.llm_url, args.model) if args.ai or args.ai_patch else []
        )
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
        scratch_backup = work / "originals"
        apply(root, changes, scratch_backup)
        unsigned = work / "unsigned.apk"
        fallback = None
        try:
            rebuild_with(args.engine, result["decoded"].engine, root, unsigned, apkeditor=apkeditor,
                         original=parts[0] if bypass else None)
        except engines.EngineError as error:
            if not (args.engine == "auto" and apkeditor and engines.resource_failure(str(error))):
                raise
            fallback = str(error).splitlines()[0][:200]
            console.print("Apktool rebuild failed on resources; retrying with APKEditor (aapt2-independent).")
            notes.append("Engine fallback: " + fallback)
            result = prepare(args, parts[0], work, "apkeditor", apkeditor=apkeditor, recipe=recipe,
                             notes=notes, bypass=bypass, apks=parts)
            root, changes = result["root"], result["changes"]
            if not changes:
                console.print("No allowlisted changes after fallback. Skipping rebuild.")
                return 0
            shutil.rmtree(scratch_backup, ignore_errors=True)
            apply(root, changes, scratch_backup)
            rebuild_with("apkeditor", "apkeditor", root, unsigned, apkeditor=apkeditor,
                         original=parts[0] if bypass else None)
        signed = work / "signed.apk"
        credentials = identity(args)
        sign(unsigned, work, signed, credentials)
        if bundle:
            signed = _pack_bundle(signed, parts, work, credentials)
        shutil.copytree(scratch_backup, backup)
        with out.open("xb") as dst, signed.open("rb") as src:
            shutil.copyfileobj(src, dst)
        engine_used = result["decoded"].engine
        write_report(report, apk, sorted(set(result["hits"]) | set(result["evidence"])), result["safety"],
                     result["evidence"], changes, notes, detected, engine_used, fallback, args,
                     result["stats"], "base APK")
        if bundle:
            import shlex
            console.print("Install with SAI, or in a fresh directory run:", soft_wrap=True)
            console.print(f"unzip {shlex.quote(str(out))} && adb install-multiple ./*.apk")
        console.print(f"Saved {out} and {report}")
    return 0


def assess_for_selective(apk, parts, recipe):
    """Assess hazards from DEX strings when no decoded tree exists."""
    from .evidence import assess_apk

    return assess_apk([apk, *parts], recipe=recipe)


def rebuild_with(requested, actual, root, output, *, apkeditor, original=None):
    if actual == "apkeditor":
        if not apkeditor:
            raise engines.EngineError("APKEditor is no longer available")
    elif requested == "apkeditor":
        raise engines.EngineError("APKEditor decode was requested but Apktool output was staged")
    return rebuild.rebuild(root, output, original=original, engine=actual, jar=apkeditor)


def write_report(report, apk, families, safety, evidence, changes, notes, detected,
                 engine, fallback, args, stats, scope):
    with report.open("x", encoding="utf-8") as stream:
        stream.write("# APK Surgeon privacy report\n\n")
        stream.write(f"APK Surgeon: {__version__}\nInput: {apk.name}\nScope: {scope}\nEngine: {engine}\n")
        if fallback:
            stream.write(f"Engine fallback reason: {fallback}\n")
        stream.write("\nDetected SDKs: " + ", ".join(families) + "\n")
        if detected:
            stream.write("Detected native frameworks: " + ", ".join(detected) + "\n")
            stream.write("Caveat: " + frameworks.FRAMEWORK_CAVEAT + "\n")
        stream.write("\nPatch Safety Verdict: " + safety["verdict"] + "\n")
        for reason in safety.get("reasons", []):
            stream.write("- " + reason + "\n")
        if args.force_unsafe and safety["verdict"].startswith("BLOCKED"):
            stream.write("- --force-unsafe override used on a Pairip BLOCKED APK.\n")
        if getattr(args, "recipe", None):
            stream.write(f"\nRecipe: {args.recipe}\n")
        for flag, label in ((args.sinkhole, "Telemetry sinkholing"),
                            (args.trust_user_ca, "User CA trust"),
                            (args.allow_screenshots, "Screenshot allowance")):
            if flag:
                stream.write(f"Opt-in patch: {label}\n")
        if stats.get("sinkholed"):
            stream.write(f"Sinkholed URLs: {len(stats['sinkholed'])}\n")
            for value in sorted(set(stats["sinkholed"])):
                stream.write(f"- {value} -> {sinkhole.SINKHOLE}\n")
        if stats.get("screenshots"):
            stream.write(f"FLAG_SECURE calls neutralized: {stats['screenshots']}\n")
        for line in notes:
            stream.write("Note: " + line + "\n")
        stream.write("\nStatic evidence:\n")
        for name in evidence:
            for signal in evidence[name]:
                stream.write(f"- {name}: {signal}\n")
        stream.write("\nChanged files:\n")
        for path in changes:
            stream.write("- " + str(path) + "\n")
        stream.write("\nSignature verified. Runtime functionality and network behavior require device testing.\n")


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
    clean = sub.choices["clean"]
    clean.add_argument("-o", "--output", type=Path)
    clean.add_argument("--smali-only", action="store_true")
    clean.add_argument("--abi", choices=ABIS)
    clean.add_argument("--yes", action="store_true")
    for flag in ("strip-ad-permissions", "disable-providers", "ai-patch"):
        clean.add_argument("--" + flag, action="store_true")
    for flag in ("keystore", "ks-alias", "ks-pass"):
        clean.add_argument("--" + flag)
    clean.add_argument("--ai", action="store_true")
    clean.add_argument("--llm-url", default="http://localhost:11434/v1")
    clean.add_argument("--model", default="qwen3:4b")
    for flag in ("merge-splits", "selective-dex", "sinkhole", "trust-user-ca",
                 "allow-screenshots", "force-unsafe"):
        clean.add_argument("--" + flag, action="store_true")
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
