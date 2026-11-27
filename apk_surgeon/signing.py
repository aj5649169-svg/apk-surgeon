"""Local signing identity and APK layout checks."""
import os
import re
import secrets
import shutil
import struct
import subprocess
import tempfile
import zipfile
from pathlib import Path

from . import repack


def resolve_identity(*, keystore=None, ks_alias=None, ks_pass=None):
    """Resolve signing keystore, alias and password env for apksigner."""
    supplied = keystore or os.getenv("APK_SURGEON_KEYSTORE")
    password = ks_pass or os.getenv("APK_SURGEON_KS_PASS") or os.getenv("APK_SURGEON_PASSWORD")
    alias = ks_alias or os.getenv("APK_SURGEON_ALIAS", "surgeon")
    if supplied:
        key = Path(supplied).expanduser().resolve(strict=True)
        if not password:
            raise ValueError("Set APK_SURGEON_KS_PASS for the supplied keystore")
    else:
        directory = Path.home() / ".apk-surgeon"
        directory.mkdir(mode=0o700, exist_ok=True)
        key = directory / "keystore.jks"
        credential = directory / "keystore.pass"
        if not key.exists():
            lock = directory / "creating-key.lock"
            with lock.open("x"):
                try:
                    if not key.exists():
                        password = password or secrets.token_urlsafe(32)
                        with tempfile.TemporaryDirectory(dir=directory) as tmp:
                            new = Path(tmp) / "key"
                            subprocess.run(["keytool", "-genkeypair", "-storetype", "JKS", "-keystore", str(new),
                                            "-storepass:env", "KS_SECRET", "-keypass:env", "KS_SECRET",
                                            "-alias", alias, "-keyalg", "RSA", "-keysize", "3072",
                                            "-validity", "3650", "-dname", "CN=APK Surgeon Local"],
                                           env={**os.environ, "KS_SECRET": password}, check=True)
                            new.chmod(0o600)
                            secret = Path(tmp) / "password"
                            secret.touch(mode=0o600)
                            secret.write_text(password)
                            secret.replace(credential)
                            new.replace(key)
                finally:
                    lock.unlink()
        password = password or credential.read_text()
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
    command = ["zipalign", "-P", "16", "-f", "4", str(source), str(dest)]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode:
        message = result.stderr + result.stdout
        if not re.search(r"(unknown|invalid|unrecognized|illegal) option", message, re.I):
            raise ValueError("zipalign failed: " + message)
        subprocess.run(["zipalign", "-p", "-f", "4", str(source), str(dest)], check=True)
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
    subprocess.run(["apksigner", "sign", "--ks", str(key), "--ks-key-alias", alias,
                    "--ks-pass", "env:KS_SECRET", "--key-pass", "env:KS_SECRET",
                    "--out", str(dest), str(aligned)], check=True, env=env)
    subprocess.run(["apksigner", "verify", "--verbose", str(dest)], check=True)
    check_layout(dest)
    return dest


def sign(source, work, dest, credentials):
    """Strip stale metadata, align for 16 KiB pages, then sign and verify."""
    return finalize(source, work, dest, credentials=credentials, unsigned=False)
