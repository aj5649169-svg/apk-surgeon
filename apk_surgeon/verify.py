"""Read-only checks for signed APKs and installable split sets."""
import re
import struct
import subprocess
import zipfile

from .signing import check_layout


def verify(parts):
    results = []
    for part in parts:
        row = {"apk": part.name, "errors": [], "certificates_sha256": [], "schemes": {}}
        sidecar = part.with_suffix(".apk.idsig")
        flags = ["--v4-signature-file", str(sidecar)] if sidecar.is_file() else []
        result = subprocess.run(["apksigner", "verify", "--verbose", "--print-certs", *flags, str(part)],
                                capture_output=True, text=True)
        for scheme, value in re.findall(r"Verified using (v[\d.]+) scheme[^:\n]*:\s*(true|false)", result.stdout):
            row["schemes"][scheme] = value == "true"
        for scheme in ("v1", "v2", "v3", "v4"):
            row["schemes"].setdefault(scheme, None)
        if result.returncode:
            row["errors"].append((result.stderr or result.stdout or "Signature verification failed").strip()[:1000])
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
