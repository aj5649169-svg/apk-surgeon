"""Local signing identity and APK layout checks."""
import os
import re
import secrets
import shutil
import struct
import subprocess
import tempfile
import threading
import time
import zipfile
from pathlib import Path

from . import engines, repack

_KEYGEN_LOCK = threading.Lock()


def _acquire_key_lock(lock, key):
    """Create and immediately close ``lock``, recovering abandoned locks on Windows/POSIX."""
    deadline = time.monotonic() + 15.0
    while True:
        try:
            with lock.open("x") as handle:
                handle.write(f"{os.getpid()}\n")
            return True
        except FileExistsError:
            if key.exists():
                return False
            try:
                stat = lock.stat()
            except FileNotFoundError:
                continue
            age = time.time() - stat.st_mtime
            if age > 30.0 or (stat.st_size == 0 and age > 2.0):
                lock.unlink(missing_ok=True)
                continue
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"Timed out waiting for signing keystore lock at {lock}; remove it if no signing job is active."
                ) from None
            time.sleep(0.1)


def resolve_identity(*, keystore=None, ks_alias=None, ks_pass=None):
    """Resolve signing keystore, alias and password env for apksigner."""
    supplied = keystore or os.getenv("APK_SURGEON_KEYSTORE")
    password = ks_pass or os.getenv("APK_SURGEON_KS_PASS") or os.getenv("APK_SURGEON_PASSWORD")
    alias = ks_alias or os.getenv("APK_SURGEON_ALIAS", "surgeon")
    if supplied:
        key = Path(supplied).expanduser().resolve(strict=True)
        if not password:
            raise ValueError("Set APK_SURGEON_KS_PASS or supply ks_pass for the provided keystore")
    else:
        directory = Path.home() / ".apk-surgeon"
        directory.mkdir(mode=0o700, exist_ok=True)
        key = directory / "keystore.jks"
        credential = directory / "keystore.pass"
        with _KEYGEN_LOCK:
            if not key.exists():
                lock = directory / "creating-key.lock"
                acquired = _acquire_key_lock(lock, key)
                try:
                    if not key.exists():
                        password = password or secrets.token_urlsafe(32)
                        with tempfile.TemporaryDirectory(dir=directory) as tmp:
                            new = Path(tmp) / "key"
                            keytool = engines.resolve_executable("keytool")
                            try:
                                subprocess.run(
                                    [keytool, "-genkeypair", "-storetype", "JKS", "-keystore", str(new),
                                     "-storepass:env", "KS_SECRET", "-keypass:env", "KS_SECRET",
                                     "-alias", alias, "-keyalg", "RSA", "-keysize", "3072",
                                     "-validity", "3650", "-dname", "CN=APK Surgeon Local"],
                                    env={**os.environ, "KS_SECRET": password},
                                    check=True, capture_output=True, text=True,
                                )
                            except FileNotFoundError as error:
                                raise ValueError(
                                    f"Signing failed: 'keytool' executable not found on PATH ({error})."
                                ) from error
                            except subprocess.CalledProcessError as error:
                                detail = (error.stderr or error.stdout or "").strip()
                                raise ValueError(
                                    f"keytool failed creating signing key (exit {error.returncode}): {detail}".strip()
                                ) from error
                            new.chmod(0o600)
                            secret = Path(tmp) / "password"
                            secret.touch(mode=0o600)
                            secret.write_text(password, encoding="utf-8")
                            secret.replace(credential)
                            new.replace(key)
                finally:
                    if acquired:
                        lock.unlink(missing_ok=True)
        if not password:
            if not credential.is_file():
                raise ValueError(
                    f"Signing keystore exists at {key} without {credential}; pass --ks-pass or remove {key}."
                )
            password = credential.read_text(encoding="utf-8")
    return key, alias, {**os.environ, "KS_SECRET": password}


def identity(args):
    """CLI argparse wrapper around :func:`resolve_identity`."""
    return resolve_identity(keystore=args.keystore, ks_alias=args.ks_alias, ks_pass=args.ks_pass)


def check_layout(apk):
    with zipfile.ZipFile(apk) as z, open(apk, "rb") as stream:
        for item in z.infolist():
            if item.filename == "resources.arsc" and item.compress_type != zipfile.ZIP_STORED:
                raise ValueError("resources.arsc must be uncompressed")
            if item.is_dir() or item.compress_type != zipfile.ZIP_STORED:
                continue
            alignment = 16384 if item.filename.startswith("lib/") and item.filename.endswith(".so") else 4
            stream.seek(item.header_offset + 26)
            name, extra = struct.unpack("<HH", stream.read(4))
            if item.compress_type != zipfile.ZIP_STORED or (item.header_offset + 30 + name + extra) % alignment:
                raise ValueError(f"{item.filename} requires {alignment}-byte alignment; install current Build Tools")


def align(source, dest):
    zipalign = engines.resolve_executable("zipalign")
    command = [zipalign, "-P", "16", "-f", "4", str(source), str(dest)]
    try:
        result = subprocess.run(command, capture_output=True, text=True)
    except FileNotFoundError as error:
        raise ValueError(
            "zipalign executable not found on PATH; install Android SDK build-tools and add it to PATH."
        ) from error
    if result.returncode:
        message = (result.stderr or result.stdout or "").strip()
        if not re.search(r"(unknown|invalid|unrecognized|illegal) option", message, re.I):
            raise ValueError("zipalign failed: " + (message or f"exit {result.returncode}"))
        try:
            subprocess.run(
                [zipalign, "-p", "-f", "4", str(source), str(dest)],
                check=True, capture_output=True, text=True,
            )
        except subprocess.CalledProcessError as error:
            detail = (error.stderr or error.stdout or "").strip()
            raise ValueError("zipalign failed: " + (detail or f"exit {error.returncode}")) from error
    check_layout(dest)


def finalize(source, work, dest, *, credentials=None, unsigned=False):
    """Strip stale metadata, enforce ZIP_STORED, align for 16 KiB pages, and optionally sign."""
    work = Path(work)
    prepared = work / "prepared.zip"
    repack.repack(source, prepared, strip_metadata=True)
    repack.verify_storage(prepared)
    aligned = work / "aligned.apk"
    align(prepared, aligned)
    if unsigned:
        shutil.copyfile(aligned, dest)
        check_layout(dest)
        return dest
    if credentials is None:
        raise ValueError("Signing credentials are required unless unsigned=True")
    key, alias, env = credentials
    apksigner = engines.resolve_executable("apksigner")
    for subcmd, argv in (
        (
            "sign",
            [apksigner, "sign", "--ks", str(key), "--ks-key-alias", alias,
             "--ks-pass", "env:KS_SECRET", "--key-pass", "env:KS_SECRET",
             "--out", str(dest), str(aligned)],
        ),
        ("verify", [apksigner, "verify", "--verbose", str(dest)]),
    ):
        try:
            subprocess.run(
                argv, check=True, env=env if subcmd == "sign" else None, capture_output=True, text=True
            )
        except FileNotFoundError as error:
            raise ValueError(
                "apksigner executable not found on PATH; install Android SDK build-tools and add it to PATH."
            ) from error
        except subprocess.CalledProcessError as error:
            detail = (error.stderr or error.stdout or "").strip()[:1500]
            raise ValueError(
                f"apksigner {subcmd} failed (exit {error.returncode}): {detail or 'no diagnostic output'}"
            ) from error
    check_layout(dest)
    return dest


def sign(source, work, dest, credentials):
    """Strip stale metadata, align for 16 KiB pages, then sign and verify."""
    return finalize(source, work, dest, credentials=credentials, unsigned=False)
