"""Static observations. Endpoint and authentication evidence grants no patch permission."""
import re

from . import dex_scanner, frameworks, layout

HOSTS = {
    "app-measurement.com": "Google Measurement",
    "firebase-settings.crashlytics.com": "Firebase Crashlytics",
    "graph.facebook.com": "Meta App Events", "inapps.appsflyer.com": "AppsFlyer",
    "api.mixpanel.com": "Mixpanel", "api.amplitude.com": "Amplitude Classic",
    "sentry.io": "Sentry", "api.branch.io": "Branch", "onesignal.com": "OneSignal",
    "googleads.g.doubleclick.net": "Google AdMob", "events.adjust.com": "Adjust",
    "sdk.iad-01.braze.com": "Braze",
}
KEYS = {
    "com.google.android.gms.ads.APPLICATION_ID": "Google AdMob",
    "com.facebook.sdk.ApplicationId": "Meta App Events",
    "io.branch.sdk.BranchKey": "Branch", "com.appsflyer.ApiKey": "AppsFlyer",
}
LITERAL = re.compile(r'^\s*const-string(?:/jumbo)?\s+[vp]\d+,\s*"([^"\n]*)"', re.M)
HOST = re.compile(r'(?:https?://|^)(?:[a-z0-9-]+\.)*?(' +
                  "|".join(map(re.escape, HOSTS)) + r')(?=[:/?#]|$)', re.I)
HAZARDS = [
    ("HIGH RISK", r"com[/.]google[/.]android[/.]play[/.]core[/.]integrity|\bStandardIntegrityManager\b|"
                  r"\bIntegrityManagerFactory\b|\bIntegrityManager\b|SafetyNetClient",
     "Play Integrity or SafetyNet may reject a re-signed build."),
    ("HIGH RISK", r"com[/.]google[/.]firebase[/.]appcheck|FirebaseAppCheck|PlayIntegrityAppCheckProvider",
     "Firebase App Check may reject a re-signed build."),
    ("HIGH RISK", r"GET_SIGNATURES|GET_SIGNING_CERTIFICATES|PackageInfo;->(?:signatures|signingInfo)|"
                  r"SigningInfo;->|getApkContentsSigners",
     "Signing certificate inspection is present. App behavior may depend on its original signer."),
    ("CAUTION", r"com[/.]google[/.]android[/.]gms[/.]auth[/.]api[/.]signin",
     "Google Sign-In may return DEVELOPER_ERROR for the new certificate."),
    ("CAUTION", r"com[/.]facebook[/.]login[/.]",
     "Facebook Login may reject the new signing key hash."),
]
HAZARDS = [(level, re.compile(pattern), reason) for level, pattern, reason in HAZARDS]
PAIRIP = re.compile(r"com[/.]pairip[/.]|Lcom/pairip/|com\.pairip\.")


def endpoints(text):
    return {match[1].lower() for literal in LITERAL.finditer(text)
            for match in HOST.finditer(literal[1])}


def _manifest_keys(tree):
    if tree is None:
        return []
    return tree.xpath("//meta-data/@android:name", namespaces={
        "android": "http://schemas.android.com/apk/res/android"})


def assess(root, tree, *, apks=(), recipe=None):
    """Return (evidence, safety).  ``apks`` enables library/Pairip inspection."""
    evidence = {}
    reasons = set()
    pairip_text = []
    for path in layout.smali_files(root):
        text = path.read_text(encoding="utf-8")
        for host in endpoints(text):
            evidence.setdefault(HOSTS[host], set()).add("endpoint: " + host)
        for level, pattern, reason in HAZARDS:
            if pattern.search(text):
                reasons.add((level, reason))
        if not pairip_text and PAIRIP.search(text):
            pairip_text.append(text)
    for key in _manifest_keys(tree):
        if key in KEYS:
            evidence.setdefault(KEYS[key], set()).add("manifest key: " + key)
    blocked, blocked_reasons = frameworks.pairip_detected(list(apks), pairip_text)
    if tree is None and apks:
        for apk in apks:
            try:
                found = dex_scanner.find_matches(apk, list(KEYS) + list(HOSTS))
            except (OSError, dex_scanner.DexError):
                found = {}
            for dex, matched in found.items():
                for needle in matched:
                    if needle in KEYS:
                        evidence.setdefault(KEYS[needle], set()).add(f"dex string ({apk.name}:{dex})")
    detected = frameworks.detect(list(apks))
    if blocked:
        verdict = "BLOCKED (Pairip VM)"
        reasons = {("BLOCKED (Pairip VM)", reason) for reason in blocked_reasons}
    else:
        verdict = ("HIGH RISK" if any(level == "HIGH RISK" for level, _ in reasons)
                   else "CAUTION" if reasons else "SAFE")
    return {name: sorted(values) for name, values in evidence.items()}, {
        "verdict": verdict,
        "reasons": sorted(reason for _, reason in reasons),
        "detected_frameworks": detected,
        "caveat": frameworks.FRAMEWORK_CAVEAT if detected else "",
        "blocked": blocked,
    }


def assess_apk(apks, *, recipe=None):
    """Assess hazards from an APK without decoding it (selective DEX path)."""
    apks = list(apks)
    blocked, blocked_reasons = frameworks.pairip_detected(apks)
    detected = frameworks.detect(apks)
    reasons = sorted(blocked_reasons)
    return {}, {
        "verdict": "BLOCKED (Pairip VM)" if blocked else "SAFE",
        "reasons": reasons,
        "detected_frameworks": detected,
        "caveat": frameworks.FRAMEWORK_CAVEAT if detected else "",
        "blocked": blocked,
    }
