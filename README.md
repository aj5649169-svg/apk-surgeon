# APK Surgeon

Find known Android tracking SDKs, review an exact patch, and build a locally signed copy. Use it for personal privacy audits on APKs you own or have authorization to modify. Check licensing and distribution permissions before sharing modified software.

`v0.6.0` expands tracker & sinkhole coverage across 39 SDK families with
AndroidX App Startup `<meta-data>` handling, paginated/searchable WebUI file
browsing (including binary hex preview), XHR upload progress, and WebUI
Privacy Studio inputs for `--tracker-db` and custom keystores alongside the
v0.5 raw APK toolkit (`decode`, `build`, `merge`, `sign`, `inspect`),
streaming raw ZIP repack, ELF 16 KiB `PT_LOAD` checks, DEX 041 container
scanning, APKEditor fallback, selective multi-DEX patching, telemetry URL
sinkholing, Pairip detection, and opt-in audit patches.

## Quick start

Install Python 3.10+, Java 17, Apktool 3.0.3+, and Android SDK Build Tools 35+
(including `zipalign` and `apksigner`). Run from a clone:

```sh
pip install -e .
apk-surgeon doctor
apk-surgeon ui                 # launch local WebUI workbench in browser
apk-surgeon inspect app.apk
apk-surgeon scan app.apk
apk-surgeon clean app.apk -o review/app-clean.apk
```

## Local WebUI workbench (`apk-surgeon ui`)

Launch the zero-dependency dark-mode workbench over localhost (`127.0.0.1:8765`) for interactive inspection, privacy auditing, unified diff preview, raw Apktool/APKEditor decode/build/merge/sign flows, live YAML recipe validation, and streaming SSE logs:

```sh
apk-surgeon ui
apk-surgeon ui --port 9000 --no-browser
```

The server binds to `127.0.0.1` by default, enforces a per-session CSRF token plus `Host`/`Origin` validation, and invokes `apk_surgeon.toolkit` directly in Python.

## Raw APK toolkit (`decode`, `build`, `merge`, `sign`, `inspect`)

`apk-surgeon` can act as a safe, 16 KiB–aligned drop-in wrapper over Apktool and APKEditor without requiring privacy patches:

```sh
# Fast read-only inspection (file size, ABIs, DEX versions, Pairip, frameworks, aapt2 badging)
apk-surgeon inspect app.apk --json

# Decode cleanly (auto-falls back to APKEditor on resource decode failures; --force to overwrite)
apk-surgeon decode app.apk -o work/app-decoded
apk-surgeon decode app.apk -o work/smali-only -r     # skip resources (-r / --no-res)
apk-surgeon decode app.apk -o work/res-only -s       # skip smali (-s / --no-src)

# Rebuild from decoded tree (auto-detects Apktool vs APKEditor, 16 KiB zipalign + sign by default)
apk-surgeon build work/app-decoded -o dist/app-rebuilt.apk
apk-surgeon build work/app-decoded -o dist/app-unsigned.apk --unsigned

# Merge split bundles (.xapk / .apkm / .apks), normalize extractNativeLibs, align and sign
apk-surgeon merge app.xapk --abi arm64-v8a -o dist/standalone.apk

# Re-sign any APK safely (strips stale META-INF/Play stamps, enforces ZIP_STORED + 16 KiB zipalign)
apk-surgeon sign app-unsigned.apk -o dist/app-signed.apk
```

Input APKs are never modified in place. Core Python helpers are importable from
`apk_surgeon.toolkit` (`decode_apk`, `build_apk`, `merge_bundle`, `sign_apk`, `inspect_apk`).

Use a fresh output directory. Read the unified diff and enter **y** to approve. Pass `--yes` for unattended deterministic patches. Originals of edited files are saved in `app-clean.backups/`; the input APK stays intact. The output directory also receives `privacy-report.md`.

Example scan (abbreviated):

```text
SDK                  Package prefix                     Matched hooks
Firebase Analytics   com.google.firebase.analytics      logEvent(Ljava/lang/String;Landroid/os/Bundle;)V
Privacy Score: 96/100 (static SDK presence heuristic)
Patch Safety Verdict: SAFE
Engine: apktool decode: default
```

The score subtracts four points per detected SDK family. Bundled code can be dormant. A score of 100 only means no built-in SDK evidence was found. When native
code is present the score is printed with a caveat, because smali patches cannot
reach Flutter, Unity, React Native or Xamarin/MAUI internals.

## Patch scope

Scan inspects decoded manifest components and known package directories across every DEX file, in either decoded layout. The cleaner disables explicitly allowlisted receiver/service names and inserts an early return into exact concrete smali signatures. Providers, constructors, native methods, register-based methods and boolean methods without a spare local are left alone. Some SDKs are detection-only, especially ad, attribution and notification products whose initialization can affect app startup. Encrypted strings, native telemetry, dynamic code and first-party analytics are outside this scope.

Signing reuses a local JKS at `~/.apk-surgeon/keystore.jks`. Back up this key and the adjacent password file securely. Both use owner-only permissions on POSIX. On Windows protect the directory with your user ACL. To reuse your own signing identity, set `APK_SURGEON_KEYSTORE`, `APK_SURGEON_ALIAS`, and `APK_SURGEON_PASSWORD` (same store and key password). A different signing certificate prevents updating over the publisher's app and can break integrations and signature checks. Test on a spare device or emulator before relying on a cleaned app. Signature verification alone cannot establish launch behavior or tracking suppression.

## Engines (`--engine auto|apktool|apkeditor`)

`--engine apktool` is the default workflow. `--engine apkeditor` decodes with
[REAndroid/APKEditor](https://github.com/REAndroid/APKEditor) `V1.4.9`
(Apache-2.0 ARSCLib) and rebuilds without `aapt2` at all, which is what you need
for obfuscated resource tables:

```sh
curl -fsSL -o APKEditor-1.4.9.jar \
  https://github.com/REAndroid/APKEditor/releases/download/V1.4.9/APKEditor-1.4.9.jar
apk-surgeon clean obfuscated.apk -o review/clean.apk --engine apkeditor --apkeditor-jar APKEditor-1.4.9.jar
```

APKEditor is detected through `--apkeditor-jar`, `APK_SURGEON_APKEDITOR_JAR`, or
an `apkeditor` executable on `PATH`. `doctor` reports it as optional and never
fails when it is absent.

`--engine auto` (default) tries Apktool first. If decoding fails, or if the
rebuild fails with a resource/`aapt2` error, the whole patch is re-applied on an
APKEditor decode, so both `AndroidManifest.xml` and smali are still patched. The
engine used and the fallback reason appear in the CLI output and in
`privacy-report.md`. Without APKEditor the error message suggests
`--apkeditor-jar` or `--smali-only`.

APKEditor decodes resources in XML mode first, then retries `-t json` and
`-t raw` when obfuscation defeats XML. In those modes resource XML files are not
editable, which the report states explicitly.

## Split bundles and `--merge-splits`

```sh
apk-surgeon clean app.xapk -o review/app.apks              # patch the base only
apk-surgeon clean app.apkm --abi arm64-v8a -o review/app.apks
apk-surgeon clean app.apks --merge-splits -o review/standalone.apk
```

`.xapk`, `.apkm` and `.apks` inputs must contain one already-selected install
set. `aapt2` identifies the base by manifest metadata; only base code is scanned
and patched, and every split is aligned and signed with the same key before the
flat SAI-style archive is written. `--merge-splits` instead merges the selected
splits (honouring `--abi`) into one standalone APK with
`APKEditor m -clean-meta`, then runs the full scan/patch/align/sign pipeline on
that single APK. Merging requires APKEditor. Universal `bundletool` variant
collections, encrypted archives and OBB payloads are unsupported.

Every repack, whichever engine produced it, strips stale signature and Play
metadata (`META-INF/MANIFEST.MF`, `META-INF/*.SF|RSA|DSA|EC`,
`META-INF/BNDLTOOL.*`, `stamp-cert-sha256`), keeps `resources.arsc` and all
`lib/**/*.so` entries at `ZIP_STORED`, then runs `zipalign -P 16 -f 4` before
`apksigner`. APKEditor aligns stored libraries at 4096 bytes only, so this step
is mandatory for Android 15-16 16 KiB page compliance.

## Selective multi-DEX patching (`--selective-dex`)

```sh
apk-surgeon clean big.apk --selective-dex --sinkhole -o review/big.apk
```

A pure-Python DEX string-pool scanner reads only the 112-byte header and
`string_ids` table of each `classes*.dex` (bounds checked, MUTF-8 safe, DEX
035-041). Only the DEX files that actually mention a tracker package, hook class
or telemetry host are disassembled, patched and reassembled; the result is
spliced back into a copy of the original APK so every other entry — including
`resources.arsc`, `res/` and native libraries — keeps its exact bytes and
compression flags. Any malformed DEX or failed splice falls back to a full
decode. Selective mode patches DEX files only, so it refuses to run together
with manifest-editing flags. `--smali-only` uses the same path automatically on
multi-DEX APKs.

## Telemetry sinkholing (`--sinkhole`)

`scan` always lists sinkholeable URLs (and `--json` includes them). `clean
--sinkhole` rewrites matching `const-string` / `const-string/jumbo` literals to
`https://127.0.0.1/`, preserving the register and instruction form and never
touching control flow — which is why it is safe for R8-minified and
non-void/object-returning methods.

Only a curated pure-telemetry allowlist is eligible: Google Analytics for
Firebase measurement, AdMob/ad serving, Adjust, AppsFlyer, Mixpanel, Amplitude,
Sentry ingest, Crashlytics, Microsoft telemetry, Braze, Segment, MIUI analytics,
Flurry, Branch and legacy analytics buckets. Shared core domains
(`googleapis.com`, `firebaseio.com`, `identitytoolkit.googleapis.com`,
`graph.facebook.com`, `googleusercontent.com`, `gstatic.com`,
`cloudfront.net`, `amazonaws.com`, `apple.com`, `play.googleapis.com`) are
hard-denied in code. Custom telemetry domains outside the built-in allowlist are
rejected by default; pass `--allow-custom-domains` to permit non-allowlisted
custom domains from a `--recipe` (logged as a warning in console output and
`privacy-report.md`).

## Frameworks, Pairip and the safety verdict

`scan --json` reports `detected_frameworks` for Flutter (`libapp.so`,
`libflutter.so`), Unity (`libil2cpp.so`, `libunity.so`), React Native
(`libhermes.so`, `libreactnativejni.so`, `libjsc.so`) and Xamarin/MAUI
(`libmonodroid.so`), across the base APK and splits.

The verdict is one of:

| Verdict | Meaning |
| --- | --- |
| `BLOCKED (Pairip VM)` | `com.pairip.*` classes or `libpairipcore.so` found. Static re-signing cannot work. |
| `HIGH RISK` | Play Integrity / `StandardIntegrityManager`, Firebase App Check, or hardcoded `GET_SIGNING_CERTIFICATES` + digest checks. |
| `CAUTION` | Certificate-bound OAuth/login (Google Sign-In, Facebook Login). |
| `SAFE` | No known re-signing hazard found in the decoded code. |

`clean` refuses a Pairip-protected APK even with `--yes`. The message names
local VPN firewalls (RethinkDNS, TrackerControl) as the working alternative. The
only override is an explicit `--force-unsafe`, and the override is recorded in
`privacy-report.md`. A reference can be dormant and signature verification says
nothing about launch behavior; device testing is still required.

## Power-user audit flags

```sh
# Inspect your own traffic with mitmproxy / HTTP Toolkit / PCAPdroid
apk-surgeon clean app.apk -o review/mitm.apk --trust-user-ca

# Neutralize literal FLAG_SECURE window flags (screenshots on your own device)
apk-surgeon clean app.apk -o review/shots.apk --allow-screenshots

# Declarative extra patches
apk-surgeon clean app.apk -o review/recipe.apk --recipe my-recipe.yml
apk-surgeon clean app.apk --recipe my-recipe.yml --sinkhole -o review/both.apk
```

`--trust-user-ca` creates `res/xml/apk_surgeon_network_security_config.xml`
trusting the `system` and `user` certificate stores and wires
`android:networkSecurityConfig` on `<application>`. If the manifest already
references a different config, the tool refuses instead of silently replacing
it. It is ignored with a warning under `--smali-only`, because the manifest is
not rebuilt in that mode.

`--allow-screenshots` rewrites only an immediately-adjacent literal
`const/16 vX, 0x2000` feeding `Window;->setFlags(II)V` or `addFlags(I)V`. Any
dynamic bitmask (an `or-int`, a computed flag) is left untouched.

`--recipe` accepts strict YAML (`PyYAML`):

```yaml
version: 1
package_prefixes: [com.example.tracker]
methods:
  - class: Lcom/example/tracker/Track;
    method: send(Ljava/lang/String;)V
  - Lcom/example/tracker/More;->log()V
disable_components: [com.example.tracker.Receiver]
sinkhole_domains: [api.segment.io]
```

Unknown fields, non-concrete signatures, malformed packages, protected sinkhole
domains and YAML syntax errors fail with the offending field and, where YAML
provides it, the line and column.

## Optional local review

```sh
apk-surgeon clean app.apk -o review/app-clean.apk --ai --llm-url http://localhost:11434/v1 --model qwen3:4b
```

Only candidate method snippets are sent to the local endpoint (up to 12 methods, 12,000 characters each). The analyzer accepts structured JSON findings. With `--ai` they remain advisory. `--ai-patch` offers each eligible exact method diff separately. Even with `--yes`, each proposal requires y/n/q. The tool generates the instructions itself and rebuilds in scratch before publishing output. Review semantics carefully; a valid no-op can still break application behavior. Keep the server and its logs private.

## Verification

```sh
apk-surgeon scan release.apk --json > scan.json
apk-surgeon verify review/app.apks --json
```

Each APK must pass `apksigner` verification, stored-file alignment (4 bytes, or
16 KiB for stored native libraries) and resource-table storage checks. Every
split must have the base signer set. JSON includes signer SHA-256 digests,
per-scheme status, per-APK errors and overall success. An unreported scheme is
`null`; detached v4 signatures need the matching `.idsig` file and are usually
absent from distributed bundles. Failure exits nonzero.

## Development

```sh
pip install -e '.[test]'
pytest -q
ruff check .
```

CI builds synthetic APKs, then exercises Apktool and APKEditor round trips,
`--merge-splits`, `--selective-dex`, `--sinkhole`, Pairip `BLOCKED` plus
`--force-unsafe`, framework detection, `--trust-user-ca`, `--allow-screenshots`,
`--recipe` and `verify --json` (including 16 KiB `.so` alignment and
`apksigner` validity). Run the same suite locally with Java, the Android tools on
`PATH`, `TEST_ANDROID_JAR` pointing at an SDK `android.jar`, and
`APK_SURGEON_APKEDITOR_JAR` pointing at `APKEditor-1.4.9.jar`.

Use Apktool 3.0.3 or newer (CVE-2026-39973 affects 3.0.0/3.0.1) and Android
Build Tools 35+. The legacy `zipalign` fallback is accepted only if the resulting
resource table and stored native libraries actually satisfy alignment checks.
ZIP alignment cannot fix an incompatible ELF binary.

## Tested toolchain matrix

| Component | Tested version (CI & Release) | Purpose |
| --- | --- | --- |
| Python | 3.10 – 3.12 (`3.12` in CI) | Core CLI, DEX 035–041 scanner, ZIP repack |
| Java (Temurin JDK) | 17 | `keytool`, Apktool, APKEditor, `apksigner` |
| Android SDK Build Tools | 35.0.0 (`platforms;android-35`) | `zipalign -P 16 -f 4`, `apksigner`, `aapt2` |
| Apktool | 3.0.3 | Default decode/rebuild engine |
| APKEditor | V1.4.9 (optional) | Aapt2-free decode/rebuild fallback & `merge` |

## Responsible use

APK Surgeon is built for personal privacy auditing, security research, and
repairing or inspecting APKs you own or have explicit authorization to modify.
Do not use it to redistribute commercial software, bypass licensing/DRM, or
tamper with apps you lack permission to analyze. Always respect upstream
licenses and test modified APKs on a non-production device.

## License and scope

APK Surgeon is MIT licensed. APKEditor is a separate Apache-2.0 project that the
tool invokes as an external process; it is not bundled or redistributed. Only
use this on software you own or are authorized to modify, and respect the
publisher's terms before sharing a modified build.
