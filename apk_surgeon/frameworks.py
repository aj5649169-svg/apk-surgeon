"""Native framework and protection-scheme detection.

Static re-signing cannot patch code that is compiled into a native engine and
it definitely cannot defeat Google Play's Pairip VM.  Detecting both up front
keeps the tool honest instead of shipping a broken APK.
"""

import zipfile

from . import dex_scanner

LIBRARY_MARKERS = {
    "libapp.so": "Flutter",
    "libflutter.so": "Flutter",
    "libil2cpp.so": "Unity",
    "libunity.so": "Unity",
    "libhermes.so": "React Native",
    "libreactnativejni.so": "React Native",
    "libjsc.so": "React Native",
    "libmonodroid.so": "Xamarin/MAUI",
}

PAIRIP_LIBS = ("libpairipcore.so",)
PAIRIP_CLASSES = ("com/pairip/", "com.pairip.", "Lcom/pairip/")
PAIRIP_STRINGS = ("com.pairip.VMRunner", "com.pairip.LicenseClient", "com.pairip.StartupLauncher")

FRAMEWORK_CAVEAT = (
    "Native framework present: method-level smali patches cannot reach engine or "
    "native telemetry. Expect partial coverage at best."
)


def libraries(apks):
    """Yield ``(apk_path, member_name)`` for every lib/**/*.so entry."""
    for apk in apks:
        try:
            with zipfile.ZipFile(apk) as archive:
                for name in archive.namelist():
                    if name.startswith("lib/") and name.endswith(".so"):
                        yield apk, name
        except (OSError, zipfile.BadZipFile):
            continue


def detect(apks):
    """Return the sorted set of native frameworks found across APKs."""
    found = set()
    for _, name in libraries(apks):
        found.add(LIBRARY_MARKERS.get(name.rsplit("/", 1)[-1], ""))
    found.discard("")
    return sorted(found)


def has_pairip_library(apks):
    return any(name.rsplit("/", 1)[-1] in PAIRIP_LIBS for _, name in libraries(apks))


def pairip_strings(apks):
    """Detect Pairip from DEX string pools without decoding the whole APK."""
    hits = []
    for apk in apks:
        try:
            found = dex_scanner.find_matches(apk, PAIRIP_STRINGS)
        except (OSError, zipfile.BadZipFile, dex_scanner.DexError):
            found = {}
        for dex, matched in found.items():
            for needle in matched:
                if needle != "<malformed>":
                    hits.append(f"{apk.name}:{dex}: {needle}")
    return sorted(set(hits))


def pairip_detected(apks, smali_texts=()):
    """Return (blocked, reasons) for Google Play Pairip protection."""
    reasons = []
    if has_pairip_library(apks):
        reasons.append("libpairipcore.so is bundled under lib/*/")
    for sample in pairip_strings(apks):
        reasons.append("Pairip VM string: " + sample)
    for text in smali_texts:
        if any(marker in text for marker in PAIRIP_CLASSES):
            reasons.append("Pairip VM classes are present (com.pairip.*)")
            break
    return bool(reasons), sorted(set(reasons))
