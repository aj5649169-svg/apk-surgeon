# Agent guardrails

Permanent rules for this repository. They exist because the tool rewrites and
re-signs APKs that people install on real devices.

## Verification

- Run `pytest -q` after every substantive change. `ruff check .` must also pass.
- Never install a JDK, Android SDK, build-tools, Apktool or APKEditor in a cloud
  sandbox. Tests that need them are guarded by `TEST_ANDROID_JAR` and run in
  GitHub Actions, which provisions Java 17, Build Tools 35, Apktool 3.0.3 and
  APKEditor 1.4.9.
- Never mark a test `skip` to make a failure disappear. A missing optional tool
  may skip; a broken assertion may not.

## Process hygiene

- Never pass `shell=True` to `subprocess`, and never build a command string that
  a shell would interpret. Always pass an argv list.
- Never run idle `sleep` loops. Poll a real condition, or wait for the tool.
- Commands run with a timeout; a hung `java` process must be killed by PID.
- Agent skills live in `.agents/skills/` for local use only and are gitignored.
  Install them with the `npx skills add ... --agent claude-code` commands listed
  in `V040_DESIGN_AND_RESEARCH.md` (kept outside the patch).

## APK safety

- Never modify the input APK in place. Decode and rebuild in a scratch directory,
  then copy the result to a fresh output path.
- Always keep `.backups/` copies of edited files and the `y/n` approval prompt
  (bypassed only with `--yes`).
- Always preserve `zipfile.ZIP_STORED` for `resources.arsc` and `lib/**/*.so`.
  Compressing either breaks Android 11-16 installation and 16 KiB page mapping.
- Always strip stale `META-INF/MANIFEST.MF`, `META-INF/*.SF|RSA|DSA|EC`,
  `META-INF/BNDLTOOL.*` and `stamp-cert-sha256` before signing.
- Always run `zipalign -P 16 -f 4` after any rebuild (Apktool *or* APKEditor) and
  before `apksigner`. APKEditor aligns stored native libraries at 4096 bytes
  only.
- Never sinkhole a shared core domain (`googleapis.com`, `firebaseio.com`,
  `graph.facebook.com`, `googleusercontent.com`, `gstatic.com`,
  `cloudfront.net`, `amazonaws.com`, `apple.com`, `play.googleapis.com`).
- Never patch code inside a Pairip-protected APK unless the user passed
  `--force-unsafe` explicitly. Refuse with an actionable alternative instead.
- Keep `--smali-only`, `--selective-dex` and `--merge-splits` semantics honest:
  if manifest edits are skipped, say so in output and in `privacy-report.md`.

## Compatibility

- Keep every v0.1-v0.3 CLI flag, JSON key and directory layout working. JSON
  changes are additive only. `Privacy Score` still subtracts 4 points per
  detected SDK family.
- Both decoded layouts must work without special cases: Apktool
  (`smali/`, `smali_classes2/`) and APKEditor (`smali/classes/`,
  `smali/classes2/`). Use `apk_surgeon.layout`, never `root.glob("smali*")`.
