import re
import shutil
import subprocess
import zipfile

from . import binary, engines

ABIS = ("arm64-v8a", "armeabi-v7a", "armeabi", "x86_64", "x86", "riscv64", "mips64", "mips")


def _split_metadata(path, entry_name, aapt2, timeout):
    """Return ``((package, version_code), split_name)`` via aapt2 with AXML fallback."""
    try:
        dump = subprocess.check_output(
            [aapt2, "dump", "badging", str(path)], stderr=subprocess.STDOUT, text=True, timeout=timeout
        )
    except FileNotFoundError:
        with zipfile.ZipFile(path) as split_zip:
            if "AndroidManifest.xml" not in split_zip.namelist():
                raise ValueError(f"Missing AndroidManifest.xml in split {entry_name}") from None
            info = binary.read_axml_manifest(split_zip.read("AndroidManifest.xml"))
        if not info["valid"] or not info["package"]:
            raise ValueError(f"Unreadable split metadata in {entry_name}") from None
        ver = info["version_code"]
        if info["version_code_major"] is not None:
            ver = (info["version_code_major"] << 32) | ((ver or 0) & 0xFFFFFFFF)
        return (info["package"], "" if ver is None else str(ver)), info["split"] or ""
    except subprocess.TimeoutExpired as error:
        raise ValueError(f"aapt2 timed out inspecting split {entry_name} after {timeout:.0f}s.") from error
    except subprocess.CalledProcessError as error:
        detail = (error.output or "").strip()[:400]
        raise ValueError(f"aapt2 failed inspecting split {entry_name}: {detail}") from error
    metadata = re.search(r"^package: (.*)$", dump, re.M)
    if not metadata:
        raise ValueError("Unreadable split metadata")
    fields = dict(re.findall(r"(\w+)='([^']*)'", metadata[1]))
    return (fields["name"], fields.get("versionCode", "")), fields.get("split", "")


def unpack(source, work):
    """Return base first. Extract to generated names, never archive-controlled paths."""
    if source.suffix.lower() == ".apk":
        return [source]
    if source.suffix.lower() not in {".apks",".xapk",".apkm"}:
        raise ValueError("Expected APK or ZIP-based APKS/XAPK/APKM")
    aapt2 = engines.resolve_executable("aapt2")
    parts = {}
    identity = None
    with zipfile.ZipFile(source) as archive:
        names = set(archive.namelist())
        for entry in archive.infolist():
            if entry.filename.lower().endswith(".obb"):
                raise ValueError("Bundles with OBB expansion files are unsupported")
            if not entry.filename.lower().endswith(".apk"):
                continue
            path = work/f"part-{len(parts)}.apk"
            with archive.open(entry) as src, path.open("wb") as dst:
                shutil.copyfileobj(src,dst)
            engines.check_cancelled("Split metadata inspection")
            timeout = engines.effective_timeout()
            current, split = _split_metadata(path, entry.filename, aapt2, timeout)
            if identity and identity != current or split in parts or not re.fullmatch(r"[\w.]*",split):
                raise ValueError("Expected one package/version and a single installable split set")
            identity = current
            named = work / (f"split_{split}.apk" if split else "base.apk")
            path.rename(named)
            sidecar = entry.filename + ".idsig"
            if sidecar in names:
                with archive.open(sidecar) as src, named.with_suffix(".apk.idsig").open("wb") as dst:
                    shutil.copyfileobj(src, dst)
            parts[split] = named
    if "" not in parts:
        raise ValueError("Missing base APK")
    return [parts.pop(""),*parts.values()]

def select_abi(parts, requested):
    def architecture(part):
        token = part.stem.removeprefix("split_").split(".")[-1].replace("-", "_")
        return next((abi for abi in ABIS if abi.replace("-", "_") == token), None)
    found = sorted({architecture(part) for part in parts[1:]} - {None})
    if requested and found and requested not in found:
        raise ValueError(f"ABI {requested} unavailable. Available: {', '.join(found)}")
    return [parts[0], *(p for p in parts[1:] if requested is None or architecture(p) in (None, requested))], found
