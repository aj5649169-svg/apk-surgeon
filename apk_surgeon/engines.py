"""Decode/rebuild engines: Apktool and REAndroid APKEditor.

APKEditor (``V1.4.9``, Apache-2.0 ARSCLib) is aapt2-independent, which makes it
the reliable fallback for obfuscated resource tables that Apktool cannot
decode.  It never aligns shared libraries for 16 KiB pages (build option
``-extractNativeLibs false`` aligns at 4096 only), so callers must always run
``zipalign -P 16 -f 4`` afterwards.
"""

import contextvars
import os
import queue
import re
import shutil
import signal
import subprocess
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

ENV_JAR = "APK_SURGEON_APKEDITOR_JAR"
ENV_TIMEOUT = "APK_SURGEON_TIMEOUT"
DEFAULT_TIMEOUT = 300.0
DOWNLOAD = "https://github.com/REAndroid/APKEditor/releases/download/V1.4.9/APKEditor-1.4.9.jar"
RESOURCE_ERROR = re.compile(
    r"aapt2|invalid resource|could not decode|failed to decode|resource table|"
    r"brut\.androlib\.res|AndroidManifest\.xml.*(?:error|invalid)|"
    r"unknown resource|no resource found|multiple resources",
    re.I,
)
DECODE_TYPES = ("xml", "json", "raw")
_EXEC_HOOKS = contextvars.ContextVar("_EXEC_HOOKS", default=None)


class EngineError(ValueError):
    """A decode or rebuild failed; the message is safe to show to users."""


class CancelledError(EngineError):
    """Raised when a user or server shutdown cancels an active tool execution."""


def effective_timeout(timeout=None):
    """Return timeout seconds for tool invocations (positive float)."""
    if timeout is not None:
        return float(timeout)
    raw = os.getenv(ENV_TIMEOUT)
    if not raw:
        return DEFAULT_TIMEOUT
    try:
        parsed = float(raw)
        return parsed if parsed > 0 else DEFAULT_TIMEOUT
    except ValueError:
        return DEFAULT_TIMEOUT


@contextmanager
def execution_hooks(*, on_line=None, cancel_event=None, on_pid=None, timeout=None):
    """Bind streaming/cancellation callbacks to the active job execution context."""
    token = _EXEC_HOOKS.set({
        "on_line": on_line,
        "cancel_event": cancel_event,
        "on_pid": on_pid,
        "timeout": timeout,
    })
    try:
        yield
    finally:
        _EXEC_HOOKS.reset(token)


def check_cancelled(what="Job"):
    """Raise CancelledError if the active execution context was cancelled."""
    hooks = _EXEC_HOOKS.get()
    ev = hooks.get("cancel_event") if hooks else None
    if ev is not None and ev.is_set():
        raise CancelledError(f"{what} cancelled by user.")


def terminate_process_tree(pid):
    """Kill a hung or cancelled subprocess tree by PID without invoking a shell."""
    pid = int(pid)
    if os.name == "nt":
        try:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True, timeout=10)
            return
        except (OSError, subprocess.SubprocessError):
            pass
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
        return
    try:
        os.killpg(os.getpgid(pid), signal.SIGKILL)
    except OSError:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


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


def _format_failure(what, returncode, combined):
    lines = combined.splitlines()
    useful = [line for line in lines if re.search(r"error|exception|failed|invalid|could not", line, re.I)]
    detail = "\n".join((useful or lines)[-6:])[:1500]
    return f"{what} failed (exit {returncode}).\n{detail}" if detail else f"{what} failed (exit {returncode})."


def run(argv, what, *, timeout=None):
    """Run a tool with timeout protection, optional live streaming, and PID-tree cancellation."""
    check_cancelled(what)
    hooks = _EXEC_HOOKS.get()
    limit = effective_timeout(timeout if timeout is not None else (hooks.get("timeout") if hooks else None))
    on_line = hooks.get("on_line") if hooks else None
    cancel_event = hooks.get("cancel_event") if hooks else None
    on_pid = hooks.get("on_pid") if hooks else None

    if on_line is None and cancel_event is None and on_pid is None:
        try:
            result = subprocess.run(argv, capture_output=True, text=True, timeout=limit)
        except OSError as error:
            cmd = argv[0] if argv else what
            hint = " (not found on PATH or not executable)" if isinstance(error, FileNotFoundError) else ""
            raise EngineError(f"{what} could not start {cmd!r}{hint}: {error}") from error
        except subprocess.TimeoutExpired as error:
            raise EngineError(f"{what} timed out after {limit:.0f}s.") from error
        if result.returncode:
            raise EngineError(_format_failure(what, result.returncode, result.stdout + "\n" + result.stderr))
        return result

    popen_kwargs = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
        "text": True,
        "errors": "replace",
    }
    if os.name != "nt":
        popen_kwargs["start_new_session"] = True
    try:
        proc = subprocess.Popen(argv, **popen_kwargs)
    except OSError as error:
        cmd = argv[0] if argv else what
        hint = " (not found on PATH or not executable)" if isinstance(error, FileNotFoundError) else ""
        raise EngineError(f"{what} could not start {cmd!r}{hint}: {error}") from error

    if on_pid:
        on_pid(proc.pid, True)
    lines = []
    q = queue.Queue()

    def _reader():
        try:
            assert proc.stdout is not None
            for raw_line in proc.stdout:
                q.put(raw_line.rstrip("\r\n"))
        finally:
            q.put(None)

    reader = threading.Thread(target=_reader, daemon=True)
    reader.start()
    deadline = time.monotonic() + limit
    eof = False
    try:
        while not eof or not q.empty():
            if cancel_event is not None and cancel_event.is_set():
                terminate_process_tree(proc.pid)
                raise CancelledError(f"{what} cancelled by user.")
            if time.monotonic() > deadline:
                terminate_process_tree(proc.pid)
                raise EngineError(f"{what} timed out after {limit:.0f}s.")
            try:
                item = q.get(timeout=0.1)
            except queue.Empty:
                if proc.poll() is not None and reader.is_alive() is False and q.empty():
                    break
                continue
            if item is None:
                eof = True
                continue
            lines.append(item)
            if on_line and item.strip():
                on_line(item)
        rc = proc.wait(timeout=10)
    finally:
        if proc.poll() is None:
            terminate_process_tree(proc.pid)
        if proc.stdout:
            proc.stdout.close()
        if on_pid:
            on_pid(proc.pid, False)

    combined = "\n".join(lines)
    if rc:
        raise EngineError(_format_failure(what, rc, combined))
    return subprocess.CompletedProcess(argv, rc, stdout=combined, stderr="")


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
