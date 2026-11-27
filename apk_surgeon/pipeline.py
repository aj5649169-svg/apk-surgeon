"""Shared scan, clean_preview, and clean orchestration used by CLI and WebUI."""

import itertools
import re
import shutil
import tempfile
import zipfile
from pathlib import Path

from . import (
    __version__,
    audit,
    dex_scanner,
    engines,
    frameworks,
    layout,
    rebuild,
    selective,
    sinkhole,
    toolkit,
)
from .bundles import select_abi, unpack
from .evidence import assess
from .patcher import apply, diff, patch_smali, plan
from .scanner import RULES, exodus, parse_manifest, scan
from .signing import identity, sign

MAX_DIFF_LINES = 2500


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
        if isinstance(error, engines.CancelledError):
            raise
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


def sinkhole_changes(changes, root, *, dexes=None, extra=None):
    """Rewrite allowlisted telemetry URLs, optionally limited to matched DEX files."""
    found = []
    for path in layout.smali_files(root, dexes):
        rewrites = _edit(changes, path, lambda text: sinkhole.rewrite(text, extra=extra))
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
    extra_domains = recipe.sinkhole_domains if recipe else None
    if getattr(args, "sinkhole", False):
        try:
            matched = selective.dex_candidates(apk, sinkhole_hosts(recipe))
        except selective.SelectiveError:
            matched = []
        dexes = {int(name[7:-4] or 1) for name in matched} if matched else None
        stats["sinkholed"] = sinkhole_changes(changes, root, dexes=dexes, extra=extra_domains)
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
    return {
        "decoded": decoded, "root": root, "hits": hits, "evidence": evidence,
        "safety": safety, "families": family_count, "changes": changes, "stats": stats,
    }


def sinkhole_hosts(recipe=None):
    hosts = set(sinkhole.ALLOWLIST)
    if recipe:
        hosts.update(recipe.sinkhole_domains)
    return sorted(hosts)


def selective_transform(args, recipe):
    """Build the per-file transform used by the selective DEX path."""
    mapping = hooks_by_descriptor(recipe)
    extra_domains = recipe.sinkhole_domains if recipe else None

    def transform(path, text):
        found = []
        match = re.search(r"(?m)^\.class[^\n]*?\s(L[^;\s]+;)", text)
        if match and match.group(1) in mapping:
            edited = patch_smali(text, mapping[match.group(1)])
            if edited != text:
                text = edited
                found.append("method " + match.group(1))
        if getattr(args, "sinkhole", False):
            text, rewrites = sinkhole.rewrite(text, extra=extra_domains)
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
            if isinstance(error, engines.CancelledError):
                raise
            notes.append(f"Selective patch of {name} failed ({error}); using a full decode.")
            return None
        if changed:
            backups.append((name, changed))
    return working, backups


def pack_bundle(signed_base, parts, work, credentials):
    packed = work / "cleaned.apks"
    with zipfile.ZipFile(packed, "w") as archive:
        archive.write(signed_base, "base.apk")
        for index, split in enumerate(parts[1:], 1):
            dest = work / f"signed-{index}.apk"
            sign(split, work, dest, credentials)
            archive.write(dest, split.name)
    return packed


def merge_bundle(args, parts, work, apkeditor, *, notes=None):
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
    normalized = toolkit.normalize_merged_extract_native_libs(merged, work, apkeditor=apkeditor, notes=notes)
    if normalized != merged and normalized.is_file():
        shutil.copyfile(normalized, merged)
    return merged


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
                            (getattr(args, "allow_custom_domains", False), "Custom sinkhole domains"),
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


def _trackers_payload(prepared):
    rows = []
    for name in sorted(set(prepared["hits"]) | set(prepared["evidence"])):
        hit = prepared["hits"].get(name)
        rows.append({
            "name": name,
            "classes": hit.classes if hit else 0,
            "components": hit.components if hit else [],
            "hooks": [sig for _, sig in hit.hooks] if hit else [],
            "evidence": prepared["evidence"].get(name, []),
        })
    return rows


def run_scan_or_clean(
    args,
    src,
    *,
    mode,
    loaded_recipe=None,
    notes=None,
    default_output=None,
    overwrite_existing=False,
    on_event=None,
    on_scan_ready=None,
    confirm_cb=None,
    ai_review_cb=None,
    preview_dir=None,
    ops=None,
):
    """Execute ``scan``, ``clean_preview``, or ``clean`` with shared orchestration."""
    notes = [] if notes is None else list(notes)
    input_size = src.stat().st_size

    def op(name, fallback_fn):
        return getattr(ops, name, fallback_fn) if ops is not None else fallback_fn

    def emit(*, step=None, progress=None, log=None):
        if on_event:
            on_event(step=step, progress=progress, log=log)

    unpack_fn = op("unpack", unpack)
    merge_bundle_fn = op("merge_bundle", merge_bundle)
    selective_clean_fn = op("selective_clean", selective_clean)
    assess_selective_fn = op("assess_for_selective", assess_for_selective)
    prepare_fn = op("prepare", prepare)
    rebuild_with_fn = op("rebuild_with", rebuild_with)
    identity_fn = op("identity", identity)
    sign_fn = op("sign", sign)
    pack_bundle_fn = op("_pack_bundle", pack_bundle)
    write_report_fn = op("write_report", write_report)
    sinkhole_changes_fn = op("sinkhole_changes", sinkhole_changes)

    with tempfile.TemporaryDirectory() as temp:
        work = Path(temp)
        emit(step="Unpacking input", progress=15, log=f"Unpacking {src.name}...")
        parts = unpack_fn(src, work)
        bundle = src.suffix.lower() != ".apk"
        apkeditor = engines.resolve_apkeditor(getattr(args, "apkeditor_jar", None))
        bypass = bool(getattr(args, "smali_only", False))

        if getattr(args, "abi", None) and not bundle:
            raise ValueError("--abi requires a split bundle")
        if getattr(args, "merge_splits", False) and not bundle:
            raise ValueError("--merge-splits requires a .xapk, .apkm or .apks bundle")
        target_apk = src
        if getattr(args, "merge_splits", False):
            parts, _ = select_abi(parts, args.abi)
            emit(step="Merging splits", progress=25, log="Merging splits with APKEditor...")
            built = merge_bundle_fn(args, parts, work, apkeditor, notes=notes)
            emit(log="Merged splits into one standalone APK with APKEditor.")
            if built.is_file() and zipfile.is_zipfile(built):
                remaining = toolkit.apk_abis([built])
                if len(remaining) > 1:
                    notes.append(f"Warning: multiple ABIs remain after merge ({', '.join(remaining)}).")
            parts, bundle = [built], False
            target_apk = built
        elif bundle:
            parts, found = select_abi(parts, getattr(args, "abi", None))
            if len(found) > 1 and not getattr(args, "abi", None):
                notes.append("Multiple ABIs detected (" + ", ".join(found) + "); filtering with --abi is recommended.")
        if bypass:
            emit(log="Smali-only mode: manifest patches and manifest scanning are skipped. Resources stay binary.")

        detected = frameworks.detect(parts)
        blocked, blocked_reasons = frameworks.pairip_detected(parts)
        if blocked and mode == "clean" and not getattr(args, "force_unsafe", False):
            reason_lines = "\n".join("- " + reason for reason in blocked_reasons)
            raise ValueError(
                "BLOCKED (Pairip VM): Google Play Automatic Protection is present.\n"
                + (reason_lines + "\n" if reason_lines else "")
                + "Refusing to patch a Pairip-protected APK. Static re-signing cannot defeat the Pairip VM and "
                "usually produces a non-launching app. Use a local VPN firewall such as RethinkDNS or "
                "TrackerControl instead, or pass --force-unsafe to override at your own risk."
            )
        if blocked and mode == "clean" and getattr(args, "force_unsafe", False):
            notes.append("Pairip BLOCKED overridden with --force-unsafe.")

        out = None
        report = None
        backup = None
        if mode == "clean":
            raw_out = getattr(args, "output", None)
            out = Path(raw_out).expanduser().resolve() if raw_out else (
                Path(default_output).resolve()
                if default_output
                else target_apk.with_name(target_apk.stem + "-cleaned" + (".apks" if bundle else ".apk"))
            )
            if out == src.resolve():
                raise ValueError("Refusing to modify input APK in place")
            expected_ext = ".apks" if bundle else ".apk"
            report = out.parent / "privacy-report.md"
            backup = out.with_suffix(".backups")
            if out.suffix.lower() != expected_ext or (
                not overwrite_existing and any(path.exists() for path in (out, report, backup))
            ):
                raise ValueError("Use a fresh output directory with an unused .apk name")

        if mode == "clean" and bypass and getattr(args, "trust_user_ca", False):
            emit(log="Warning: --trust-user-ca cannot edit the manifest in --smali-only mode. Flag ignored.")

        if mode == "clean" and getattr(args, "selective_dex", False) and (
            getattr(args, "strip_ad_permissions", False)
            or getattr(args, "disable_providers", False)
            or getattr(args, "trust_user_ca", False)
            or (loaded_recipe and loaded_recipe.disable_components)
        ):
            raise ValueError(
                "--selective-dex patches DEX files only and cannot edit the manifest. Drop it, or drop "
                "--strip-ad-permissions/--disable-providers/--trust-user-ca/manifest recipe components."
            )

        selective_result = None
        if mode == "clean" and (
            getattr(args, "selective_dex", False) or (bypass and not getattr(args, "trust_user_ca", False))
        ):
            emit(step="Selective DEX scan", progress=40, log="Scanning DEX string pools...")
            selective_result = selective_clean_fn(args, parts[0], work, loaded_recipe, notes)

        if selective_result:
            staged, backups = selective_result
            evidence, safety = assess_selective_fn(staged, parts[1:], loaded_recipe)
            families = sorted(evidence)
            score = max(0, 100 - 4 * len(families))
            if not backups:
                return {
                    "ok": True,
                    "noop": True,
                    "notes": notes,
                    "safety": safety,
                    "privacy_score": score,
                    "engine": "apktool-selective",
                    "summary": {"privacy_score_before": score, "engine": "apktool-selective"},
                }
            if confirm_cb and not confirm_cb([f"patched {line}" for _, files in backups for line in files]):
                return {"ok": True, "aborted": True, "notes": notes, "safety": safety, "privacy_score": score}
            out.parent.mkdir(parents=True, exist_ok=True)
            if overwrite_existing and backup.exists():
                shutil.rmtree(backup)
            backup.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(parts[0]) as archive:
                for name, _ in backups:
                    (backup / (name + ".bak")).write_bytes(archive.read(name))
            emit(step="Signing output", progress=80, log="Aligning & signing selective APK...")
            signed = work / "signed.apk"
            creds = identity_fn(args)
            sign_fn(staged, work, signed, creds)
            if bundle:
                signed = pack_bundle_fn(signed, parts, work, creds)
            if overwrite_existing:
                shutil.copyfile(signed, out)
                if report.exists():
                    report.unlink()
            else:
                with out.open("xb") as dst, signed.open("rb") as stream:
                    shutil.copyfileobj(stream, dst)
            changes = {Path(name): "" for name, _ in backups}
            write_report_fn(
                report, target_apk, families, safety, evidence, changes, notes, detected,
                "apktool-selective", None, args, {"sinkholed": [], "screenshots": 0}, "base APK",
            )
            return {
                "ok": True,
                "output": str(out),
                "report": str(report),
                "engine": "apktool-selective",
                "safety": safety,
                "privacy_score": score,
                "notes": notes,
                "changed_files": [str(k) for k in changes],
                "summary": {
                    "input_size": input_size,
                    "output_size": out.stat().st_size,
                    "privacy_score_before": score,
                    "engine": "apktool-selective",
                },
            }

        emit(step="Decoding & scanning", progress=45, log=f"Decoding with {args.engine} engine...")
        prepared = prepare_fn(
            args, parts[0], work, args.engine,
            apkeditor=apkeditor, recipe=loaded_recipe, notes=notes, bypass=bypass, apks=parts,
        )
        root, changes = prepared["root"], prepared["changes"]
        extra_domains = loaded_recipe.sinkhole_domains if loaded_recipe else None
        candidates = sorted(set(sinkhole_changes_fn({}, root, extra=extra_domains)))
        external = exodus(root, args.tracker_db) if getattr(args, "tracker_db", None) else []
        score = max(0, 100 - 4 * prepared["families"])
        trackers = _trackers_payload(prepared)
        changed_rel = [p.relative_to(root).as_posix() for p in changes]

        if on_scan_ready:
            on_scan_ready(prepared, detected, candidates, external, notes)

        if mode in {"scan", "clean_preview"}:
            diff_lines = [line.rstrip("\n") for line in itertools.islice(diff(root, changes), MAX_DIFF_LINES)]
            if len(diff_lines) == MAX_DIFF_LINES:
                diff_lines.append("... (diff truncated for preview)")
            artifacts = {}
            if preview_dir is not None:
                diff_path = Path(preview_dir) / "preview.diff"
                diff_path.write_text("\n".join(diff_lines) + ("\n" if diff_lines else ""), encoding="utf-8")
                artifacts["diff"] = diff_path
                manifest_p = None if bypass else layout.manifest(root)
                if manifest_p and manifest_p.is_file():
                    manifest_art = Path(preview_dir) / "AndroidManifest.xml"
                    shutil.copy2(manifest_p, manifest_art)
                    artifacts["manifest"] = manifest_art
            return {
                "ok": True,
                "version": __version__,
                "privacy_score": score,
                "trackers": trackers,
                "safety": prepared["safety"],
                "exodus": external,
                "scope": "base APK",
                "detected_frameworks": detected,
                "engine": prepared["decoded"].engine,
                "decode_type": prepared["decoded"].decode_type,
                "notes": notes,
                "sinkhole": {"candidates": candidates, "endpoint": sinkhole.SINKHOLE},
                "changed_files": changed_rel,
                "diff_lines": diff_lines,
                "stats": prepared["stats"],
                "artifacts": artifacts,
                "summary": {
                    "privacy_score": score,
                    "changes_count": len(changed_rel),
                    "verdict": prepared["safety"]["verdict"],
                },
            }

        if external:
            prepared["evidence"].setdefault("Exodus", []).extend(external)

        if ai_review_cb and (getattr(args, "ai", False) or getattr(args, "ai_patch", False)):
            if ai_review_cb(root, changes) is False:
                return {"ok": True, "aborted": True, "notes": notes, "safety": prepared["safety"], "privacy_score": score}

        if not changes:
            return {
                "ok": True,
                "noop": True,
                "notes": notes,
                "safety": prepared["safety"],
                "privacy_score": score,
                "engine": prepared["decoded"].engine,
                "summary": {"privacy_score_before": score, "engine": prepared["decoded"].engine},
            }

        if confirm_cb and not confirm_cb(list(diff(root, changes))):
            return {"ok": True, "aborted": True, "notes": notes, "safety": prepared["safety"], "privacy_score": score}

        diff_lines = [line.rstrip("\n") for line in itertools.islice(diff(root, changes), MAX_DIFF_LINES)]
        out.parent.mkdir(parents=True, exist_ok=True)
        scratch_backup = work / "originals"

        emit(step="Applying & rebuilding", progress=65, log="Applying patches and rebuilding...")
        apply(root, changes, scratch_backup)
        unsigned_apk = work / "unsigned.apk"
        fallback = None
        try:
            rebuild_with_fn(
                args.engine, prepared["decoded"].engine, root, unsigned_apk,
                apkeditor=apkeditor, original=parts[0] if bypass else None,
            )
        except engines.EngineError as error:
            if isinstance(error, engines.CancelledError):
                raise
            if not (args.engine == "auto" and apkeditor and engines.resource_failure(str(error))):
                raise
            fallback = str(error).splitlines()[0][:200]
            notes.append("Engine fallback: " + fallback)
            emit(log="Apktool rebuild failed on resources; retrying with APKEditor...")
            prepared = prepare_fn(
                args, parts[0], work, "apkeditor",
                apkeditor=apkeditor, recipe=loaded_recipe, notes=notes, bypass=bypass, apks=parts,
            )
            root, changes = prepared["root"], prepared["changes"]
            if not changes:
                return {
                    "ok": True,
                    "noop": True,
                    "notes": notes,
                    "safety": prepared["safety"],
                    "privacy_score": score,
                    "engine": "apkeditor",
                }
            shutil.rmtree(scratch_backup, ignore_errors=True)
            apply(root, changes, scratch_backup)
            rebuild_with_fn(
                "apkeditor", "apkeditor", root, unsigned_apk,
                apkeditor=apkeditor, original=parts[0] if bypass else None,
            )
            diff_lines = [line.rstrip("\n") for line in itertools.islice(diff(root, changes), MAX_DIFF_LINES)]
            changed_rel = [p.relative_to(root).as_posix() for p in changes]

        emit(step="Aligning & signing", progress=85, log="Running zipalign -P 16 and apksigner...")
        signed = work / "signed.apk"
        creds = identity_fn(args)
        sign_fn(unsigned_apk, work, signed, creds)
        if bundle:
            signed = pack_bundle_fn(signed, parts, work, creds)
        if overwrite_existing and backup.exists():
            shutil.rmtree(backup)
        shutil.copytree(scratch_backup, backup)
        if overwrite_existing:
            shutil.copyfile(signed, out)
            if report.exists():
                report.unlink()
        else:
            with out.open("xb") as dst, signed.open("rb") as stream:
                shutil.copyfileobj(stream, dst)
        write_report_fn(
            report, target_apk, sorted(set(prepared["hits"]) | set(prepared["evidence"])),
            prepared["safety"], prepared["evidence"], changes, notes, detected,
            prepared["decoded"].engine, fallback, args, prepared["stats"], "base APK",
        )
        artifacts = {}
        if preview_dir is not None:
            diff_file = Path(preview_dir) / "patch.diff"
            diff_file.write_text("\n".join(diff_lines) + ("\n" if diff_lines else ""), encoding="utf-8")
            artifacts["diff"] = diff_file
        return {
            "ok": True,
            "output": str(out),
            "report": str(report),
            "bundle": bundle,
            "engine": prepared["decoded"].engine,
            "fallback": fallback,
            "privacy_score": score,
            "safety": prepared["safety"],
            "trackers": _trackers_payload(prepared),
            "stats": prepared["stats"],
            "notes": notes,
            "changed_files": changed_rel,
            "artifacts": artifacts,
            "summary": {
                "input_size": input_size,
                "output_size": out.stat().st_size,
                "privacy_score_before": score,
                "engine": prepared["decoded"].engine,
                "sinkholed": len(prepared["stats"].get("sinkholed", [])),
                "screenshots": prepared["stats"].get("screenshots", 0),
            },
        }
