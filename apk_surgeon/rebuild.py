import copy
import re
import shutil
import subprocess
import zipfile


def rebuild(root, output, original=None):
    result = subprocess.run(["apktool", "b", str(root), "-o", str(output)], capture_output=True, text=True)
    if result.returncode:
        lines = (result.stdout + "\n" + result.stderr).splitlines()
        useful = [s for s in lines if re.search(r"error:|aapt2|invalid resource|failed to compile", s, re.I)]
        detail = "\n".join((useful or lines)[0:6])[:1500]
        hint = "\nRetry clean with --smali-only to preserve compiled resources." if useful and not original else ""
        raise ValueError("Apktool rebuild failed.\n" + detail + hint)
    if original:
        # Only transplant assembled DEX. Even unknown resource encodings survive.
        merged = output.with_suffix(".merged.apk")
        with zipfile.ZipFile(original) as src, zipfile.ZipFile(output) as built, zipfile.ZipFile(merged, "w") as dst:
            for entry in src.infolist():
                source = built if re.fullmatch(r"classes(?:[2-9]|[1-9]\d+)?\.dex", entry.filename) else src
                with source.open(entry.filename) as inp, dst.open(copy.copy(entry), "w") as out:
                    shutil.copyfileobj(inp, out)
        merged.replace(output)
