"""Core Layer-1 APK toolkit operations.

Clean, importable Python functions for ``decode``, ``build``, ``merge``,
``sign`` and ``inspect`` that never shell out to ``apk-surgeon`` itself,
never touch input APKs in place, and always return JSON-serializable dicts.
"""

import re
import shutil
import struct
import subprocess
import tempfile
import zipfile
from pathlib import Path

from . import binary, bundles, dex_scanner, engines, frameworks, layout, repack, scanner, signing, verify

_decode_axml_string_pool = binary.decode_axml_string_pool


def read_axml_extract_native_libs(data):
    """Return True/False if compiled AndroidManifest sets extractNativeLibs, else None."""
    return binary.read_axml_manifest(data)["extract_native_libs"]


def _strip_split_manifest_markers(root, application):
    """Remove split-APK requirement attributes and Play Store metadata after merge."""
    changed = False
    for manifest_attr in ("requiredSplitTypes", "splitTypes"):
        key = scanner.ANDROID + manifest_attr
        if key in root.attrib:
            del root.attrib[key]
            changed = True
    split_req_key = scanner.ANDROID + "isSplitRequired"
    if split_req_key in application.attrib:
        del application.attrib[split_req_key]
        changed = True
    name_key = scanner.ANDROID + "name"
    for meta in list(application.findall("meta-data")):
        if meta.get(name_key) in ("com.android.vending.splits", "com.android.vending.splits.required"):
            application.remove(meta)
            changed = True
    return changed


def normalize_manifest_extract_native_libs(
    manifest_path, *, has_native_libs, stored_and_aligned_16k, clean_splits=False
):
    """Set extractNativeLibs='false' only when libs are stored & 16 KiB aligned; else normalize/remove."""
    from lxml import etree

    manifest_path = Path(manifest_path)
    root = scanner.ensure_android_namespace(scanner.parse_manifest(manifest_path).getroot())
    application = root.find("application")
    if application is None:
        return False
    changed = False
    key = scanner.ANDROID + "extractNativeLibs"
    if has_native_libs and stored_and_aligned_16k:
        desired = "false"
    elif has_native_libs:
        desired = "true"
    else:
        desired = None
    current = application.get(key)
    if desired is None:
        if key in application.attrib:
            del application.attrib[key]
            changed = True
    elif current != desired:
        application.set(key, desired)
        changed = True
    if clean_splits:
        changed = _strip_split_manifest_markers(root, application) or changed
    if not changed:
        return False
    manifest_path.write_text(
        etree.tostring(root, encoding="UTF-8", xml_declaration=True).decode() + "\n", encoding="utf-8"
    )
    return True


def _inspect_native_layout(apk):
    """Return (has_native_libs, all_stored, aligned_16k) for ``apk``."""
    with zipfile.ZipFile(apk) as archive:
        native_items = [
            item for item in archive.infolist()
            if item.filename.startswith("lib/") and item.filename.endswith(".so")
        ]
    has_libs = bool(native_items)
    all_stored = all(item.compress_type == zipfile.ZIP_STORED for item in native_items)
    try:
        signing.check_layout(apk)
        layout_ok = True
    except (ValueError, OSError, struct.error, zipfile.BadZipFile):
        layout_ok = False
    return has_libs, all_stored, layout_ok


def normalize_merged_extract_native_libs(apk, work, *, apkeditor=None, notes=None):
    """Normalize AndroidManifest extractNativeLibs on a merged APK when needed."""
    apk = Path(apk)
    work = Path(work)
    notes = notes if notes is not None else []
    if not apk.is_file() or not zipfile.is_zipfile(apk):
        return apk
    work.mkdir(parents=True, exist_ok=True)
    staged = work / "norm-staged.apk"
    probed = work / "norm-probed.apk"
    repack.repack(apk, staged, strip_metadata=True)
    repack.verify_storage(staged)
    try:
        signing.align(staged, probed)
        candidate = probed
    except (ValueError, OSError, subprocess.SubprocessError):
        candidate = staged
    has_libs, all_stored, layout_ok = _inspect_native_layout(candidate)
    stored_and_16k = has_libs and all_stored and layout_ok
    desired = False if stored_and_16k else (True if has_libs else None)
    with zipfile.ZipFile(candidate) as archive:
        if "AndroidManifest.xml" not in archive.namelist():
            return candidate
        manifest_info = binary.read_axml_manifest(archive.read("AndroidManifest.xml"))
    needs_enl = manifest_info["extract_native_libs"] != desired
    needs_splits = bool(
        manifest_info["is_split_required"]
        or manifest_info["required_split_types"]
        or manifest_info["has_vending_splits"]
    )
    if not needs_enl and not needs_splits:
        label = "false" if desired is False else ("true" if desired is True else "absent")
        notes.append(f"extractNativeLibs already normalized ({label}).")
        return candidate
    if not apkeditor:
        notes.append("Skipped extractNativeLibs/split manifest normalization: APKEditor jar unavailable.")
        return candidate
    dec_dir = work / "norm-decode"
    try:
        decoded = engines.decode_apkeditor(apkeditor, candidate, dec_dir, types=("xml",))
    except engines.EngineError as error:
        notes.append(
            "Could not decode merged manifest to normalize extractNativeLibs: "
            + str(error).splitlines()[0][:160]
        )
        return candidate
    manifest_file = layout.manifest(decoded.root)
    if manifest_file is None:
        return candidate
    changed = normalize_manifest_extract_native_libs(
        manifest_file, has_native_libs=has_libs, stored_and_aligned_16k=stored_and_16k, clean_splits=True
    )
    if not changed:
        return candidate
    rebuilt = work / "norm-rebuilt.apk"
    engines.rebuild_apkeditor(apkeditor, decoded.root, rebuilt)
    with zipfile.ZipFile(rebuilt) as archive:
        if "AndroidManifest.xml" not in archive.namelist():
            return candidate
        patched_manifest = archive.read("AndroidManifest.xml")
    normalized = work / "norm-final.apk"
    repack.repack(candidate, normalized, replace={"AndroidManifest.xml": patched_manifest})
    if needs_enl:
        notes.append(
            "Normalized android:extractNativeLibs="
            + ('"false"' if stored_and_16k else ('"true"' if has_libs else "<removed>"))
            + " after split merge."
        )
    if needs_splits:
        notes.append("Cleared split-only manifest flags (isSplitRequired / vending.splits) after merge.")
    return normalized


def apk_abis(apks):
    """Return sorted native ABI names present under ``lib/<abi>/*.so`` across APKs."""
    found = set()
    for _, name in frameworks.libraries(apks):
        parts = Path(name).parts
        if len(parts) >= 3 and parts[0] == "lib":
            found.add(parts[1])
    return sorted(found)


def detect_decoded_engine(root, requested="auto"):
    """Detect whether a decoded directory was created by Apktool or APKEditor."""
    root = Path(root)
    if not root.is_dir():
        raise ValueError(f"Decoded directory not found: {root}")
    if requested in ("apktool", "apkeditor"):
        return requested
    if requested != "auto":
        raise ValueError(f"Unsupported engine: {requested}")
    if (root / "apktool.yml").is_file():
        return "apktool"
    smali = root / "smali"
    if (root / "archive-info.json").is_file() or (smali / "classes").is_dir() or (
        smali.is_dir() and any(smali.glob("classes*"))
    ) or (root / "resources").is_dir():
        return "apkeditor"
    if layout.manifest(root) is not None or layout.smali_dirs(root):
        return "apktool"
    raise ValueError(f"Cannot detect decoded APK structure in {root}")


def _check_output_file(output, *, input_path=None, force=False):
    output = Path(output).resolve()
    if input_path is not None and output == Path(input_path).resolve():
        raise ValueError("Refusing to modify input APK in place; provide a distinct output path")
    if output.exists():
        if output.is_dir():
            raise ValueError(f"Output path is a directory: {output}")
        if not force:
            raise ValueError(f"Output file already exists: {output} (pass --force to overwrite)")
    output.parent.mkdir(parents=True, exist_ok=True)
    return output


def _check_output_dir(output, *, force=False):
    output = Path(output).resolve()
    if output.exists():
        if output.is_file():
            raise ValueError(f"Output path exists and is a file: {output}")
        if not force:
            raise ValueError(f"Output directory already exists: {output} (pass --force to overwrite)")
    output.parent.mkdir(parents=True, exist_ok=True)
    return output


def decode_apk(apk, output, *, engine="auto", apkeditor_jar=None, no_res=False, no_src=False, force=False):
    """Decode an APK into ``output`` using Apktool or APKEditor (with auto-fallback)."""
    apk = Path(apk).resolve(strict=True)
    out = _check_output_dir(output, force=force)
    apkeditor = engines.resolve_apkeditor(apkeditor_jar)
    notes = []
    with tempfile.TemporaryDirectory() as temp:
        staging = Path(temp) / "decoded"
        if engine == "apkeditor":
            if not apkeditor:
                raise ValueError(
                    "--engine apkeditor needs APKEditor. Pass --apkeditor-jar PATH, set "
                    f"{engines.ENV_JAR}, or download {engines.DOWNLOAD}"
                )
            if no_res or no_src:
                notes.append("APKEditor ignores --no-res/--no-src flags.")
            result = engines.decode_apkeditor(apkeditor, apk, staging)
            notes.extend(result.notes)
        elif engine == "apktool" or not apkeditor:
            result = engines.decode_apktool(apk, staging, no_res=no_res, no_src=no_src)
        else:
            try:
                result = engines.decode_apktool(apk, staging, no_res=no_res, no_src=no_src)
            except engines.EngineError as error:
                if not engines.resource_failure(str(error)):
                    raise
                notes.append(
                    "Apktool resource decode failed; fell back to APKEditor. "
                    + str(error).splitlines()[0][:200]
                )
                if no_res or no_src:
                    notes.append("APKEditor fallback ignores --no-res/--no-src flags.")
                result = engines.decode_apkeditor(apkeditor, apk, staging)
                notes.extend(result.notes)
        if out.exists() and force:
            shutil.rmtree(out)
        shutil.copytree(result.root, out)
    return {
        "ok": True,
        "apk": str(apk),
        "output": str(out),
        "engine": result.engine,
        "decode_type": result.decode_type,
        "no_res": bool(no_res),
        "no_src": bool(no_src),
        "notes": notes,
    }


def build_apk(
    directory,
    output,
    *,
    engine="auto",
    apkeditor_jar=None,
    unsigned=False,
    force=False,
    keystore=None,
    ks_alias=None,
    ks_pass=None,
):
    """Rebuild a decoded tree, enforce storage/16 KiB alignment, and optionally sign."""
    root = Path(directory).resolve(strict=True)
    out = _check_output_file(output, force=force)
    actual_engine = detect_decoded_engine(root, requested=engine)
    apkeditor = engines.resolve_apkeditor(apkeditor_jar) if actual_engine == "apkeditor" else None
    if actual_engine == "apkeditor" and not apkeditor:
        raise ValueError(
            "APKEditor build needs APKEditor. Pass --apkeditor-jar PATH, set "
            f"{engines.ENV_JAR}, or download {engines.DOWNLOAD}"
        )
    credentials = None if unsigned else signing.resolve_identity(
        keystore=keystore, ks_alias=ks_alias, ks_pass=ks_pass
    )
    with tempfile.TemporaryDirectory() as temp:
        work = Path(temp)
        raw_built = work / "raw.apk"
        if actual_engine == "apkeditor":
            engines.rebuild_apkeditor(apkeditor, root, raw_built)
        else:
            engines.rebuild_apktool(root, raw_built)
        finished = work / "finished.apk"
        signing.finalize(raw_built, work, finished, credentials=credentials, unsigned=unsigned)
        shutil.copyfile(finished, out)
    verification = None if unsigned else verify.verify([out])
    return {
        "ok": True if verification is None else verification["ok"],
        "input": str(root),
        "output": str(out),
        "engine": actual_engine,
        "signed": not unsigned,
        "aligned": True,
        "verify": verification,
    }


def sign_apk(apk, output, *, force=False, keystore=None, ks_alias=None, ks_pass=None):
    """Strip stale signatures, enforce ZIP_STORED + 16 KiB alignment, sign and verify."""
    apk = Path(apk).resolve(strict=True)
    if apk.suffix.lower() in {".xapk", ".apkm", ".apks"}:
        raise ValueError(
            f"sign requires a standalone .apk file, got {apk.suffix}; use Merge Splits first for split bundles."
        )
    out = _check_output_file(output, input_path=apk, force=force)
    if not zipfile.is_zipfile(apk):
        raise ValueError(f"Expected a valid APK zip archive: {apk}")
    credentials = signing.resolve_identity(keystore=keystore, ks_alias=ks_alias, ks_pass=ks_pass)
    with tempfile.TemporaryDirectory() as temp:
        work = Path(temp)
        signed = work / "signed.apk"
        signing.finalize(apk, work, signed, credentials=credentials, unsigned=False)
        shutil.copyfile(signed, out)
    verification = verify.verify([out])
    return {
        "ok": verification["ok"],
        "input": str(apk),
        "output": str(out),
        "signed": True,
        "aligned": True,
        "verify": verification,
    }


def merge_bundle(
    bundle,
    output,
    *,
    abi=None,
    apkeditor_jar=None,
    unsigned=False,
    force=False,
    keystore=None,
    ks_alias=None,
    ks_pass=None,
):
    """Merge a split bundle into one standalone APK with extractNativeLibs normalization."""
    bundle = Path(bundle).resolve(strict=True)
    if bundle.suffix.lower() not in {".xapk", ".apkm", ".apks"}:
        raise ValueError("merge requires a .xapk, .apkm, or .apks split bundle")
    out = _check_output_file(output, input_path=bundle, force=force)
    apkeditor = engines.resolve_apkeditor(apkeditor_jar)
    if not apkeditor:
        raise ValueError(
            "merge requires APKEditor. Pass --apkeditor-jar PATH, set "
            f"{engines.ENV_JAR}, or download {engines.DOWNLOAD}"
        )
    credentials = None if unsigned else signing.resolve_identity(
        keystore=keystore, ks_alias=ks_alias, ks_pass=ks_pass
    )
    notes = []
    warnings = []
    with tempfile.TemporaryDirectory() as temp:
        work = Path(temp)
        parts = bundles.unpack(bundle, work)
        selected, found_split_abis = bundles.select_abi(parts, abi)
        splits_dir = work / "splits"
        splits_dir.mkdir()
        for part in selected:
            shutil.copy2(part, splits_dir / part.name)
        merged = work / "merged.apk"
        engines.merge_splits(apkeditor, splits_dir, merged)
        normalized = normalize_merged_extract_native_libs(merged, work, apkeditor=apkeditor, notes=notes)
        merged_abis = apk_abis([normalized])
        if len(merged_abis) > 1:
            warnings.append(
                f"Multiple ABIs remain after merge ({', '.join(merged_abis)}); "
                "filter with --abi if single-ABI output is wanted."
            )
        elif not merged_abis and len(found_split_abis) > 1 and not abi:
            warnings.append(f"Multiple split ABIs detected ({', '.join(found_split_abis)}); none selected.")
        finished = work / "finished.apk"
        signing.finalize(normalized, work, finished, credentials=credentials, unsigned=unsigned)
        shutil.copyfile(finished, out)
    verification = None if unsigned else verify.verify([out])
    return {
        "ok": True if verification is None else verification["ok"],
        "input": str(bundle),
        "output": str(out),
        "abis": merged_abis,
        "signed": not unsigned,
        "aligned": True,
        "warnings": warnings,
        "notes": notes,
        "verify": verification,
    }


def _parse_badging(apk):
    aapt2 = shutil.which("aapt2")
    if not aapt2:
        return None
    try:
        result = subprocess.run([aapt2, "dump", "badging", str(apk)], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode:
        return None
    stdout = result.stdout
    pkg_line = re.search(r"^package:\s*(.+)$", stdout, re.M)
    fields = dict(re.findall(r"(\w+)='([^']*)'", pkg_line.group(1))) if pkg_line else {}
    min_sdk = re.search(r"^sdkVersion:'([^']*)'", stdout, re.M)
    target_sdk = re.search(r"^targetSdkVersion:'([^']*)'", stdout, re.M)
    label = re.search(r"^application-label:'([^']*)'", stdout, re.M)
    native = re.search(r"^native-code:\s*(.+)$", stdout, re.M)
    return {
        "package": fields.get("name"),
        "version_code": fields.get("versionCode"),
        "version_name": fields.get("versionName"),
        "min_sdk": min_sdk.group(1) if min_sdk else None,
        "target_sdk": target_sdk.group(1) if target_sdk else None,
        "application_label": label.group(1) if label else None,
        "native_code": re.findall(r"'([^']+)'", native.group(1)) if native else [],
        "permissions_count": len(re.findall(r"^uses-permission:", stdout, re.M)),
    }


def _inspect_single_apk_zip(apk):
    dex_files = []
    arsc_info = {"present": False, "stored": None, "compress_type": None}
    native_count = 0
    native_all_stored = True
    elf_checked = 0
    elf_unaligned = []
    extract_native_libs = None
    with zipfile.ZipFile(apk) as archive:
        info_map = {item.filename: item for item in archive.infolist()}
        arsc = info_map.get("resources.arsc")
        if arsc is not None:
            ctype = "stored" if arsc.compress_type == zipfile.ZIP_STORED else (
                "deflated" if arsc.compress_type == zipfile.ZIP_DEFLATED else str(arsc.compress_type)
            )
            arsc_info = {"present": True, "stored": arsc.compress_type == zipfile.ZIP_STORED, "compress_type": ctype}
        if "AndroidManifest.xml" in info_map:
            extract_native_libs = read_axml_extract_native_libs(archive.read("AndroidManifest.xml"))
        for item in archive.infolist():
            if item.filename.startswith("lib/") and item.filename.endswith(".so"):
                native_count += 1
                if item.compress_type != zipfile.ZIP_STORED:
                    native_all_stored = False
                parts = Path(item.filename).parts
                abi = parts[1] if len(parts) >= 3 else ""
                with archive.open(item) as stream:
                    elf = binary.inspect_elf_alignment(stream)
                if elf is not None:
                    elf_checked += 1
                    is_64 = elf["bits"] == 64 or abi in binary.ARCH_64_ABIS
                    if is_64 and not elf["aligned_16k"]:
                        elf_unaligned.append(item.filename)
        for name in dex_scanner.dex_entries(archive):
            try:
                data = dex_scanner._read_dex(archive, name)
                headers = list(dex_scanner.iter_headers(data))
                dex_files.append({
                    "name": name,
                    "version": headers[0].version,
                    "header_size": headers[0].header_size,
                    "container_sections": len(headers),
                })
            except (dex_scanner.DexError, OSError) as error:
                dex_files.append({"name": name, "version": None, "error": str(error)})
    return {
        "dex_files": dex_files,
        "resources_arsc": arsc_info,
        "native_libs": {
            "count": native_count,
            "all_stored": native_all_stored if native_count else True,
            "elf_checked": elf_checked,
            "elf_16k_aligned": None if elf_checked == 0 else (not elf_unaligned),
            "elf_unaligned": sorted(elf_unaligned),
        },
        "extract_native_libs": extract_native_libs,
    }


def inspect_apk(apk):
    """Fast read-only APK or bundle inspection without decoding or modifying input."""
    apk = Path(apk).resolve(strict=True)
    suffix = apk.suffix.lower()
    if suffix not in {".apk", ".apks", ".xapk", ".apkm"}:
        raise ValueError("Expected APK or ZIP-based APKS/XAPK/APKM")
    if not zipfile.is_zipfile(apk):
        raise ValueError(f"Not a valid zip archive: {apk}")
    size = apk.stat().st_size
    is_bundle = suffix != ".apk"
    split_apks = []
    if not is_bundle:
        parts = [apk]
        details = _inspect_single_apk_zip(apk)
        badging = _parse_badging(apk)
        detected = frameworks.detect(parts)
        blocked, blocked_reasons = frameworks.pairip_detected(parts)
        abis = apk_abis(parts)
        return {
            "ok": True,
            "path": str(apk),
            "file": apk.name,
            "file_size": size,
            "archive_type": "apk",
            "extension": suffix,
            "abis": abis,
            "detected_frameworks": detected,
            "pairip": {"blocked": blocked, "reasons": blocked_reasons},
            "split_apks": [],
            "badging": badging,
            **details,
        }
    with tempfile.TemporaryDirectory() as temp:
        work = Path(temp)
        extracted = []
        with zipfile.ZipFile(apk) as archive:
            for item in archive.infolist():
                if not item.filename.lower().endswith(".apk"):
                    continue
                split_apks.append(item.filename)
                target = work / f"part-{len(extracted)}.apk"
                with archive.open(item) as src, target.open("wb") as dst:
                    shutil.copyfileobj(src, dst)
                extracted.append(target)
        if not extracted:
            raise ValueError("Bundle archive contains no .apk entries")
        base = extracted[0]
        aapt2 = shutil.which("aapt2")
        if aapt2:
            for candidate in extracted:
                dump = subprocess.run(
                    [aapt2, "dump", "badging", str(candidate)], capture_output=True, text=True, timeout=30
                )
                if dump.returncode == 0 and "package:" in dump.stdout and "split='" not in dump.stdout:
                    base = candidate
                    break
        else:
            for candidate in extracted:
                with zipfile.ZipFile(candidate) as sub:
                    names = set(sub.namelist())
                    if "AndroidManifest.xml" in names:
                        minfo = binary.read_axml_manifest(sub.read("AndroidManifest.xml"))
                        if minfo["valid"] and minfo["package"] and not minfo["split"]:
                            base = candidate
                            break
                    if dex_scanner.dex_entries(sub):
                        base = candidate
                        break
        details = _inspect_single_apk_zip(base)
        badging = _parse_badging(base)
        detected = frameworks.detect(extracted)
        blocked, blocked_reasons = frameworks.pairip_detected(extracted)
        abis = apk_abis(extracted)
        native_count = 0
        native_all_stored = True
        elf_checked = 0
        elf_unaligned = []
        for part in extracted:
            part_details = _inspect_single_apk_zip(part)
            nl = part_details["native_libs"]
            native_count += nl["count"]
            if nl["count"] and not nl["all_stored"]:
                native_all_stored = False
            elf_checked += nl["elf_checked"]
            elf_unaligned.extend(nl["elf_unaligned"])
        dedup_unaligned = sorted(set(elf_unaligned))
        details["native_libs"] = {
            "count": native_count,
            "all_stored": native_all_stored if native_count else True,
            "elf_checked": elf_checked,
            "elf_16k_aligned": None if elf_checked == 0 else (not dedup_unaligned),
            "elf_unaligned": dedup_unaligned,
        }
    return {
        "ok": True,
        "path": str(apk),
        "file": apk.name,
        "file_size": size,
        "archive_type": "split-bundle",
        "extension": suffix,
        "abis": abis,
        "detected_frameworks": detected,
        "pairip": {"blocked": blocked, "reasons": blocked_reasons},
        "split_apks": split_apks,
        "badging": badging,
        **details,
    }
