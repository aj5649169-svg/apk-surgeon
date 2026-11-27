"""Read-only checks for signed APKs and installable split sets."""
import re
import struct
import subprocess
import zipfile

from . import engines
from .signing import check_layout


def verify(parts):
    apksigner = engines.resolve_executable("apksigner")
    timeout = engines.effective_timeout()
    results = []
    for part in parts:
        engines.check_cancelled("APK verification")
        row = {"apk": part.name, "errors": [], "certificates_sha256": [], "schemes": {}}
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
        if results and results[0]["certificates_sha256"] != row["certificates_sha256"]:
            row["errors"].append("Signing certificates differ from base.apk")
        results.append(row)
    return {"ok": all(not row["errors"] for row in results), "apks": results}
