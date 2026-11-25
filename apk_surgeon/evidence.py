"""Static observations. Endpoint and authentication evidence grants no patch permission."""
import re

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
                  '|'.join(map(re.escape, HOSTS)) + r')(?=[:/?#]|$)', re.I)
HAZARDS = [
    ("HIGH RISK", r"com[/.]google[/.]android[/.]play[/.]core[/.]integrity|\bIntegrityManager\b|SafetyNetClient",
     "Play Integrity or SafetyNet may reject a re-signed build."),
    ("HIGH RISK", r"GET_SIGNATURES|GET_SIGNING_CERTIFICATES|PackageInfo;->(?:signatures|signingInfo)|SigningInfo;->",
     "Signing certificate inspection is present. App behavior may depend on its original signer."),
    ("CAUTION", r"com[/.]google[/.]android[/.]gms[/.]auth[/.]api[/.]signin",
     "Google Sign-In may return DEVELOPER_ERROR for the new certificate."),
    ("CAUTION", r"com[/.]facebook[/.]login[/.]",
     "Facebook Login may reject the new signing key hash."),
]
HAZARDS = [(level, re.compile(pattern), reason) for level, pattern, reason in HAZARDS]


def endpoints(text):
    return {match[1].lower() for literal in LITERAL.finditer(text)
            for match in HOST.finditer(literal[1])}


def assess(root, tree):
    evidence = {}
    reasons = set()
    for path in root.glob("smali*/**/*.smali"):
        text = path.read_text(encoding="utf-8")
        for host in endpoints(text):
            evidence.setdefault(HOSTS[host], set()).add("endpoint: " + host)
        for level, pattern, reason in HAZARDS:
            if pattern.search(text):
                reasons.add((level, reason))
    if tree is not None:
        for key in tree.xpath("//meta-data/@android:name", namespaces={
                "android": "http://schemas.android.com/apk/res/android"}):
            if key in KEYS:
                evidence.setdefault(KEYS[key], set()).add("manifest key: " + key)
    verdict = "HIGH RISK" if any(level == "HIGH RISK" for level, _ in reasons) else "CAUTION" if reasons else "SAFE"
    return {name: sorted(values) for name, values in evidence.items()}, {
        "verdict": verdict, "reasons": sorted(reason for _, reason in reasons)}
