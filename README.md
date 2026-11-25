# APK Surgeon

Find known Android tracking SDKs, review an exact patch, and build a locally signed copy. Use it for personal privacy audits on APKs you own or have authorization to modify. Check licensing and distribution permissions before sharing modified software.

## Quick start

Install Python 3.10+, Java 17, Apktool, and Android SDK Build Tools 35+ (including zipalign and apksigner). Run from a clone:

```sh
pip install -e .
apk-surgeon doctor
apk-surgeon scan app.apk
apk-surgeon clean app.apk -o review/app-clean.apk
```

Use a fresh output directory. Read the unified diff and enter **y** to approve. Pass `--yes` for unattended deterministic patches. Originals of edited files are saved in `app-clean.backups/`; the input APK stays intact. The output directory also receives `privacy-report.md`.

Example scan (abbreviated):

```text
SDK                  Package prefix                     Matched hooks
Firebase Analytics   com.google.firebase.analytics      logEvent(Ljava/lang/String;Landroid/os/Bundle;)V
Privacy Score: 96/100 (static SDK presence heuristic)
```

The score subtracts four points per detected SDK family. Bundled code can be dormant. A score of 100 only means none of the 25 package rules matched.

## Patch scope

Scan inspects decoded manifest components and known package directories across DEX files. The cleaner disables explicitly allowlisted receiver/service names and inserts an early return into exact concrete smali signatures. Providers, constructors, native methods, register-based methods and boolean methods without a spare local are left alone. Some SDKs are detection-only, especially ad, attribution and notification products whose initialization can affect app startup. Obfuscation, native telemetry, dynamic code and first-party analytics are outside this MVP.

Signing reuses a local JKS at `~/.apk-surgeon/keystore.jks`. Back up this key and the adjacent password file securely. Both use owner-only permissions on POSIX. On Windows protect the directory with your user ACL. To reuse your own signing identity, set `APK_SURGEON_KEYSTORE`, `APK_SURGEON_ALIAS`, and `APK_SURGEON_PASSWORD` (same store and key password). A different signing certificate prevents updating over the publisher’s app and can break integrations and signature checks. Test on a spare device or emulator before relying on a cleaned app. Signature verification alone cannot establish launch behavior or tracking suppression.

## Optional local review

```sh
apk-surgeon clean app.apk -o review/app-clean.apk --ai --llm-url http://localhost:11434/v1 --model qwen3:4b
```

Only candidate method snippets are sent to the local endpoint (up to 12 methods, 12,000 characters each). The analyzer accepts structured JSON findings. With --ai they remain advisory. --ai-patch offers each eligible exact method diff separately. Even with --yes, each proposal requires y/n/q. The tool generates the instructions itself and rebuilds in scratch before publishing output. Review semantics carefully; a valid no-op can still break application behavior. Keep the server and its logs private.

## Development

```sh
pip install -e '.[test]'
pytest -q
```

CI also builds a synthetic APK, runs scan and clean, verifies the resulting signature and decodes its manifest again. Run the same integration test locally with the tools on PATH and `TEST_ANDROID_JAR` pointing to an SDK platform android.jar.

## v0.2 workflows

```sh
apk-surgeon scan app.apk --tracker-db exodus-trackers.json
apk-surgeon clean app.xapk -o review/app-cleaned.apks --strip-ad-permissions
apk-surgeon clean app.apk -o review/clean.apk --ai-patch
apk-surgeon clean app.apk --keystore my.jks --ks-alias release
```

Use APK_SURGEON_KS_PASS for custom keys; --ks-pass is also accepted but can enter shell history. Updates require the same certificate, package name and compatible version codes. v0.1 temporary signing identities cannot be recovered.

ZIP-based APKS, APKM and XAPK inputs must contain one already-selected install set. aapt2 identifies the base by manifest metadata. Only base code is scanned and patched. All splits are aligned and signed with the same key, then packaged as a flat SAI-style archive. For adb, extract the archive and run adb install-multiple -r with all APK paths. Universal bundletool variant collections, encrypted archives and OBB payloads are unsupported.

The local Exodus database adds detection-only code and network regex matches; use a trusted database. The built-in score still counts curated SDK families. --strip-ad-permissions removes the three supported ad identifier/attribution permissions. --disable-providers explicitly opts into disabling known Firebase, Facebook and Sentry startup providers. This can affect non-analytics features. Shared WorkManager and AndroidX Startup infrastructure stays enabled. An empty patch list produces no output.

Use Apktool 3.0.2 or newer and Android Build Tools 35+. Legacy zipalign fallback is accepted only if the resulting resource table and stored native libraries actually satisfy alignment checks. ZIP alignment cannot fix an incompatible ELF binary.
