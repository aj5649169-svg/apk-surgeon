import re
import shutil
import subprocess
import zipfile


def unpack(source, work):
    """Return base first. Extract to generated names, never archive-controlled paths."""
    if source.suffix.lower() == ".apk":
        return [source]
    if source.suffix.lower() not in {".apks",".xapk",".apkm"}:
        raise ValueError("Expected APK or ZIP-based APKS/XAPK/APKM")
    parts = {}
    identity = None
    with zipfile.ZipFile(source) as archive:
        for entry in archive.infolist():
            if entry.filename.lower().endswith(".obb"):
                raise ValueError("Bundles with OBB expansion files are unsupported")
            if not entry.filename.lower().endswith(".apk"):
                continue
            path = work/f"part-{len(parts)}.apk"
            with archive.open(entry) as src, path.open("wb") as dst:
                shutil.copyfileobj(src,dst)
            dump = subprocess.check_output(["aapt2","dump","badging",str(path)],text=True)
            metadata = re.search(r"^package: (.*)$",dump,re.M)
            if not metadata:
                raise ValueError("Unreadable split metadata")
            fields = dict(re.findall(r"(\w+)='([^']*)'",metadata[1]))
            current = fields["name"], fields["versionCode"]
            split = fields.get("split","")
            if identity and identity != current or split in parts or not re.fullmatch(r"[\w.]*",split):
                raise ValueError("Expected one package/version and a single installable split set")
            identity = current
            parts[split] = path
    if "" not in parts:
        raise ValueError("Missing base APK")
    return [parts.pop(""),*parts.values()]
