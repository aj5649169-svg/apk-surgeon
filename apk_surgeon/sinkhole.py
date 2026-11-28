"""Telemetry URL sinkholing.

Only pure ad/analytics collection endpoints may be pointed at
``https://127.0.0.1/``.  Shared core domains that also serve logins, maps,
CDN assets or normal app features are hard-denied in code so no recipe can
re-enable them by accident.
"""

import re
from urllib.parse import urlsplit

SINKHOLE = "https://127.0.0.1/"

# Exact hosts whose only realistic purpose is telemetry/advertising.
ALLOWLIST = {
    "app-measurement.com": "Google Analytics for Firebase collection",
    "googleads.g.doubleclick.net": "Google AdMob ad requests",
    "pagead2.googlesyndication.com": "Google AdMob ad requests",
    "adservice.google.com": "Google ad serving",
    "analytics.adjust.com": "Adjust attribution",
    "app.adjust.com": "Adjust attribution",
    "events.adjust.com": "Adjust attribution",
    "inapps.appsflyer.com": "AppsFlyer attribution",
    "launches.appsflyer.com": "AppsFlyer attribution",
    "api.mixpanel.com": "Mixpanel event ingestion",
    "api.amplitude.com": "Amplitude event ingestion",
    "api2.amplitude.com": "Amplitude event ingestion",
    "ingest.sentry.io": "Sentry event ingestion",
    "e.crashlytics.com": "Crashlytics event ingestion",
    "events.data.microsoft.com": "Microsoft telemetry",
    "mobile.events.data.microsoft.com": "Microsoft telemetry",
    "in.appcenter.ms": "Microsoft App Center ingestion",
    "sdk.iad-01.braze.com": "Braze event ingestion",
    "api.segment.io": "Segment event ingestion",
    "tracking.miui.com": "MIUI analytics",
    "data.flurry.com": "Flurry analytics",
    "api.branch.io": "Branch attribution",
    "api2.branch.io": "Branch attribution",
    "analytics.s3.amazonaws.com": "Legacy analytics bucket",
    "api.clevertap.com": "CleverTap event ingestion",
    "api.leanplum.com": "Leanplum event ingestion",
    "api.singular.net": "Singular attribution",
    "heapanalytics.com": "Heap event ingestion",
    "api.countly.com": "Countly event ingestion",
    "api.tealiumiq.com": "Tealium event ingestion",
    "app.posthog.com": "PostHog event ingestion",
    "us.i.posthog.com": "PostHog event ingestion",
    "eu.i.posthog.com": "PostHog event ingestion",
}

# DSN-style hosts that carry a per-project prefix.
ALLOWLIST_PATTERNS = (
    (re.compile(r"^[a-z0-9-]+\.ingest\.sentry\.io$"), "Sentry DSN ingest"),
    (re.compile(r"^sdk\.iad-0[1-8]\.braze\.com$"), "Braze event ingestion"),
    (re.compile(r"^[a-z0-9-]+\.app-measurement\.com$"), "Google Analytics for Firebase collection"),
)

# Host + path pairs: only the logging path may be sinkholed.
PATH_ALLOWLIST = {
    "graph.instagram.com": ("/logging_client_events",),
}

# Shared infrastructure.  Never rewrite these, even with a custom recipe.
DENYLIST = (
    "googleapis.com",
    "firebaseio.com",
    "identitytoolkit.googleapis.com",
    "graph.facebook.com",
    "googleusercontent.com",
    "gstatic.com",
    "cloudfront.net",
    "amazonaws.com",
    "apple.com",
    "play.googleapis.com",
)

CONST_STRING = re.compile(
    r'(?P<prefix>^[ \t]*const-string(?:/jumbo)?[ \t]+(?P<register>[vp]\d+),[ \t]*")'
    r'(?P<value>(?:[^"\\\n]|\\.)*)'
    r'(?P<suffix>")',
    re.M,
)
URL_LITERAL = re.compile(r"^https?://[^\s\"']+$", re.I)
CUSTOM_HOST = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$")
UNESCAPE = (("\\/", "/"), ('\\"', '"'), ("\\\\", "\\"))


class DeniedDomain(ValueError):
    """Raised when a domain is explicitly protected from sinkholing."""


def normalize(host):
    return (host or "").strip().strip(".").lower()


def denied(host):
    """True when ``host`` is (a subdomain of) a protected shared domain."""
    host = normalize(host)
    return any(host == item or host.endswith("." + item) for item in DENYLIST)


def _matches_extra(host, extra):
    if not extra:
        return False
    for candidate in extra:
        item = normalize(candidate)
        if item and (host == item or host.endswith("." + item)):
            return True
    return False


def allowlisted(host, path="", *, extra=None):
    """True for pure-telemetry endpoints (or approved custom hosts not on DENYLIST)."""
    host = normalize(host)
    if not host:
        return False
    exact = host in ALLOWLIST
    if exact and not denied(host):
        return True
    if exact and host == "analytics.s3.amazonaws.com":
        return True
    for pattern, _ in ALLOWLIST_PATTERNS:
        if pattern.match(host) and not denied(host):
            return True
    prefixes = PATH_ALLOWLIST.get(host)
    if prefixes and (path or "").startswith(prefixes):
        return not denied(host)
    if _matches_extra(host, extra) and not denied(host):
        return True
    return False


def host_of(value):
    """Return (host, path) for a smali string literal, or ("", "")."""
    literal = value
    for old, new in UNESCAPE:
        literal = literal.replace(old, new)
    if not URL_LITERAL.match(literal):
        return "", ""
    try:
        parts = urlsplit(literal)
    except ValueError:
        return "", ""
    return normalize(parts.hostname or ""), parts.path or ""


def sinkholeable(value, *, extra=None):
    """True when a smali string literal is a sinkhole-eligible URL."""
    host, path = host_of(value)
    return bool(host) and allowlisted(host, path, extra=extra)


def rewrite(text, *, extra=None):
    """Rewrite allowlisted const-string URLs.  Returns (text, replacements)."""
    replacements = []

    def replace(match):
        value = match.group("value")
        if not sinkholeable(value, extra=extra):
            return match.group(0)
        replacements.append((value, SINKHOLE))
        return match.group("prefix") + SINKHOLE + match.group("suffix")

    return CONST_STRING.sub(replace, text), replacements


def candidates(text, *, extra=None):
    """Return the sinkholeable URLs present in a smali file."""
    found = []
    for match in CONST_STRING.finditer(text):
        value = match.group("value")
        if sinkholeable(value, extra=extra):
            found.append(value)
    return found


def custom_domains(domains):
    """Return sorted normalized domains that are outside the built-in telemetry allowlist."""
    return sorted({normalize(d) for d in domains if normalize(d) and not allowlisted(d)})


def validate_recipe_domains(domains, *, allow_custom=False):
    """Raise when a recipe tries to add a protected or unapproved domain."""
    normalized = [normalize(domain) for domain in domains]
    invalid = sorted({domain for domain in normalized if not CUSTOM_HOST.fullmatch(domain)})
    if invalid:
        raise ValueError("Recipe sinkhole_domains must be valid hostnames: " + ", ".join(invalid))
    protected = sorted({domain for domain in normalized if denied(domain)})
    if protected:
        raise DeniedDomain(
            "Recipe cannot sinkhole protected shared domains: " + ", ".join(protected)
            + ". These serve logins, storage or CDN assets and would break the app."
        )
    if not allow_custom:
        unknown = sorted({domain for domain in normalized if not allowlisted(domain)})
        if unknown:
            raise DeniedDomain(
                "Recipe sinkhole domain is not on the pure-telemetry allowlist: " + ", ".join(unknown)
                + ". Pass --allow-custom-domains to override with a warning, or add pure telemetry hosts to "
                "apk_surgeon/sinkhole.py."
            )
    return sorted(set(normalized))
