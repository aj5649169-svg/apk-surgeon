"""Decode/rebuild engines: Apktool and REAndroid APKEditor.

APKEditor (``V1.4.9``, Apache-2.0 ARSCLib) is aapt2-independent, which makes it
the reliable fallback for obfuscated resource tables that Apktool cannot
decode.  It never aligns shared libraries for 16 KiB pages (build option
``-extractNativeLibs false`` aligns at 4096 only), so callers must always run
``zipalign -P 16 -f 4`` afterwards.
"""

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

ENV_JAR = "APK_SURGEON_APKEDITOR_JAR"
DOWNLOAD = "https://github.com/REAndroid/APKEditor/releases/download/V1.4.9/APKEditor-1.4.9.jar"
RESOURCE_ERROR = re.compile(
    r"aapt2|invalid resource|could not decode|failed to decode|resource table|"
    r"brut\.androlib\.res|AndroidManifest\.xml.*(?:error|invalid)|"
    r"unknown resource|no resource found|multiple resources",
    re.I,
)
DECODE_TYPES = ("xml", "json", "raw")


class EngineError(ValueError):
    """A decode or rebuild failed; the message is safe to show to users."""


@dataclass
class DecodeResult:
    engine: str
    root: Path
    decode_type: str | None = None
    notes: list = field(default_factory=list)

    def as_dict(self):
        return {"engine": self.engine, "decode_type": self.decode_type, "notes": list(self.notes)}


def resolve_executable(name):
    """Resolve an executable on PATH (including Windows .cmd/.bat shims) without shell=True."""
    return shutil.which(str(name)) or str(name)


def resolve_apkeditor(explicit=None):
    """Resolve APKEditor to a jar path or executable wrapper, or None."""
    for candidate in (explicit, os.getenv(ENV_JAR)):
        if candidate:
            path = Path(candidate).expanduser()
            if path.is_file():
                return path.resolve()
            raise EngineError(f"APKEditor not found at {path}")
    found = shutil.which("apkeditor")
    return Path(found).resolve() if found else None


def apkeditor_version(target):
    """Return the APKEditor version string, or None when it cannot be read."""
    try:
        result = subprocess.run(command(target, "-v"), capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return None
    text = result.stdout + result.stderr
    match = re.search(r"(\d+\.\d+\.\d+)", text)
    return match.group(1) if match else None


def command(target, *args):
    """Build the argv for an APKEditor jar or wrapper."""
    target = Path(target)
    base = ["java", "-jar", str(target)] if target.suffix.lower() == ".jar" else [str(target)]
    return [*base, *(str(arg) for arg in args)]


def run(argv, what):
    """Run a tool, raising EngineError with a short diagnostic tail."""
    try:
        result = subprocess.run(argv, capture_output=True, text=True)
    except OSError as error:
        cmd = argv[0] if argv else what
        hint = " (not found on PATH or not executable)" if isinstance(error, FileNotFoundError) else ""
        raise EngineError(f"{what} could not start {cmd!r}{hint}: {error}") from error
    if result.returncode:
        lines = (result.stdout + "\n" + result.stderr).splitlines()
        useful = [line for line in lines if re.search(r"error|exception|failed|invalid|could not", line, re.I)]
        detail = "\n".join((useful or lines)[-6:])[:1500]
        raise EngineError(f"{what} failed (exit {result.returncode}).\n{detail}")
    return result


def resource_failure(message):
    """True when a failure looks like an aapt2/resource decoding problem."""
    return bool(RESOURCE_ERROR.search(message or ""))


def decode_apktool(apk, root, *, no_res=False, no_src=False):
    argv = [resolve_executable("apktool"), "d"]
    if no_res:
        argv.append("-r")
    if no_src:
        argv.append("-s")
    argv.extend([str(apk), "-o", str(root)])
    run(argv, "Apktool decode")
    return DecodeResult("apktool", Path(root))


def decode_apkeditor(jar, apk, root, *, types=DECODE_TYPES):
    """Decode with APKEditor, retrying less readable resource formats."""
    errors = []
    for index, kind in enumerate(types):
        target = Path(str(root) + ("" if index == 0 else f"-{kind}"))
        if target.exists():
            shutil.rmtree(target)
        try:
            run(command(jar, "d", "-t", kind, "-i", str(apk), "-o", str(target), "-f"), f"APKEditor decode (-t {kind})")
        except EngineError as error:
            errors.append(str(error))
            continue
        notes = []
        if kind != "xml":
            notes.append(f"Obfuscated resources forced APKEditor -t {kind}; resource XML files are not editable.")
        return DecodeResult("apkeditor", target, kind, notes)
    raise EngineError("APKEditor could not decode this APK in any mode.\n" + "\n".join(errors)[-1500:])


def rebuild_apktool(root, output):
    run([resolve_executable("apktool"), "b", str(root), "-o", str(output)], "Apktool rebuild")
    return output


def rebuild_apkeditor(jar, root, output):
    run(command(jar, "b", "-i", str(root), "-o", str(output), "-f"), "APKEditor rebuild")
    return output


def merge_splits(jar, source_dir, output):
    """Merge a directory of split APKs into one standalone APK."""
    run(command(jar, "m", "-i", str(source_dir), "-o", str(output), "-clean-meta", "-f"), "APKEditor merge")
    if not Path(output).is_file():
        raise EngineError("APKEditor merge did not produce an APK")
    return output


def doctor_note(target):
    if target is None:
        return (
            "APKEditor: missing (optional). Auto-fallback for obfuscated resources and "
            f"--merge-splits need it: --apkeditor-jar PATH or download {DOWNLOAD}"
        )
    return f"APKEditor: {target} (version {apkeditor_version(target) or 'unknown'})"
