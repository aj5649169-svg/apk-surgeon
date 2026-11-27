"""Read-only checks for signed APKs and installable split sets."""
import re
import struct
import subprocess
import zipfile
from pathlib import Path

from . import binary, engines
from .signing import check_layout


def _elf_alignment_warnings(apk):
    warnings = []
    try:
        with zipfile.ZipFile(apk) as archive:
            for item in archive.infolist():
                if not (item.filename.startswith("lib/") and item.filename.endswith(".so")):
                    continue
                parts = Path(item.filename).parts
                abi = parts[1] if len(parts) >= 3 else ""
                with archive.open(item) as stream:
                    elf = binary.inspect_elf_alignment(stream)
                if elf is None:
                    continue
                is_64 = elf["bits"] == 64 or abi in binary.ARCH_64_ABIS
                if is_64 and not elf["aligned_16k"]:
                    warnings.append(
                        f"{item.filename} ELF PT_LOAD alignment is {elf['min_align']} bytes "
                        "(< 16384 required for Android 15+ 16 KiB page devices)."
                    )
    except (OSError, zipfile.BadZipFile):
        pass
    return warnings


def verify(parts):
    apksigner = engines.resolve_executable("apksigner")
    timeout = engines.effective_timeout()
    results = []
    for part in parts:
        engines.check_cancelled("APK verification")
        row = {"apk": part.name, "errors": [], "warnings": [], "certificates_sha256": [], "schemes": {}}
        sidecar = part.with_suffix(".apk.idsig")
        flags = ["--v4-signature-file", str(sidecar)] if sidecar.is_file() else []
        try:
            result = subprocess.run([apksigner, "verify", "--verbose", "--print-certs", *flags, str(part)],
                                    capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError as error:
            raise ValueError(
                "apksigner executable not found on PATH; install Android SDK build-tools and add it to PATH."
            ) from error
        except subprocess.TimeoutExpired as error:
            raise ValueError(f"apksigner verify timed out after {timeout:.0f}s.") from error
        for scheme, value in re.findall(r"Verified using (v[\d.]+) scheme[^:\n]*:\s*(true|false)", result.stdout):
            row["schemes"][scheme] = value == "true"
        for scheme in ("v1", "v2", "v3", "v4"):
            row["schemes"].setdefault(scheme, None)
        if result.returncode:
            detail = "\n".join(text for text in (result.stderr.strip(), result.stdout.strip()) if text)
            row["errors"].append((detail or f"apksigner verify exited with code {result.returncode}")[:1200])
        else:
            row["certificates_sha256"] = sorted(re.findall(
                r"^Signer #\d+ certificate SHA-256 digest:\s*([a-fA-F0-9]{64})\s*$", result.stdout, re.M))
            if not row["certificates_sha256"]:
                row["errors"].append("Missing verified signer digest")
        try:
            check_layout(part)
            row["aligned"] = True
        except (ValueError, struct.error, zipfile.BadZipFile) as error:
            row["aligned"] = False
            row["errors"].append(str(error))
        row["warnings"] = _elf_alignment_warnings(part)
        if results and results[0]["certificates_sha256"] != row["certificates_sha256"]:
            row["errors"].append("Signing certificates differ from base.apk")
        results.append(row)
    return {
        "ok": all(not row["errors"] for row in results),
        "warnings": [msg for row in results for msg in row["warnings"]],
        "apks": results,
    }
