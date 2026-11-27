# APK Surgeon UI Architecture (`apk-surgeon ui`)

> Layer 2 local WebUI & developer workbench built exclusively on Python's standard library (`http.server.ThreadingHTTPServer`) and static browser assets (`apk_surgeon/ui_assets/`). Zero Node.js, Electron, or compiled Python/Rust dependencies—installs cleanly on desktop Linux/macOS/Windows and Android Termux.

---

## 1. Visual & UX Identity

- **Design Philosophy:** Precision dark-mode security workbench inspired by Linear, Raycast, and modern reverse-engineering IDEs—replacing cramped Java Swing dialogs with crisp spatial hierarchy, clear status telemetry, and zero visual clutter.
- **Color & Surface System:**
  - Canvas `#090c10` → Panel `#0f141b` → Elevated Card `#151c26` → Hairline border `rgba(148, 163, 184, 0.14)`
  - Accents: Surgical Emerald (`#10b981`) for verified actions/passes, Diagnostic Cyan (`#22d3ee`) for telemetry/active streams, Amber (`#f59e0b`) for `CAUTION` & overrides, Rose (`#f43f5e`) for `HIGH RISK` / `BLOCKED (Pairip VM)`.
- **Typography:** Local system sans-serif UI typography paired with monospace fonts (`JetBrains Mono` / `Cascadia Code` / `ui-monospace`) for DEX versions, SHA-256 digests, smali paths, unified diffs, and CLI previews. Zero external font/CDN requests (100% offline).

---

## 2. Backend Architecture (`apk_surgeon/ui.py`)

### Direct Python Calls (No CLI Sub-Shelling)
All routes invoke core library modules directly (`apk_surgeon.toolkit`, `apk_surgeon.recipe`, `apk_surgeon.scanner`, `apk_surgeon.patcher`, `apk_surgeon.evidence`, `apk_surgeon.frameworks`, `apk_surgeon.audit`, `apk_surgeon.signing`, `apk_surgeon.verify`, `apk_surgeon.engines`).

### HTTP Endpoints & SSE Streaming
| Method & Path | Purpose |
| --- | --- |
| `GET /` | Serves `index.html` with embedded per-session CSRF token in `<meta>` |
| `GET /assets/<name>` | Serves bundled CSS/JS strictly from `apk_surgeon/ui_assets/` |
| `GET /api/doctor` | Checks JDK, Build Tools 35 (`zipalign`, `apksigner`, `aapt2`), Apktool, and APKEditor |
| `POST /api/upload` | Streams large APK/bundle uploads (`X-Filename` or multipart) to temp workspace |
| `POST /api/inspect` | Runs fast read-only `toolkit.inspect_apk()` on uploaded or local APK/bundle path |
| `POST /api/detect-engine` | Detects `apktool` vs `apkeditor` layout via `toolkit.detect_decoded_engine()` |
| `POST /api/recipe/validate` | Live schema & domain allowlist/denylist validation via `recipe.loads()` |
| `POST /api/jobs` | Submits async job (`clean_preview`, `clean`, `decode`, `build`, `merge`, `sign`, `verify`, `scan`) |
| `GET /api/jobs` | Returns session job history (status, metrics, size & score deltas, artifacts) |
| `GET /api/jobs/<id>/events` | Server-Sent Events (SSE) live log/progress stream backed by `threading.Condition` |
| `GET /api/jobs/<id>/artifacts/<name>` | Downloads built `.apk`/`.apks` or reads `privacy-report.md` / diffs / manifests |
| `GET /api/workspace-file` | Read-only viewer for `AndroidManifest.xml` / files inside session-created decode dirs |

---

## 3. Security Model

1. **Loopback Binding & Rebinding Defense:**
   - Default host `127.0.0.1`; warns loudly if a non-loopback `--host` is supplied.
   - Strict `Host` header check matching bound host/loopback, plus `Origin` verification on API/mutating calls (`403` on mismatch).
2. **Per-Session CSRF Token:**
   - Generated via `secrets.token_urlsafe(32)` on startup, embedded in `<meta name="apk-surgeon-token">`, and verified in constant time (`hmac.compare_digest`) via `X-APK-Surgeon-Token` on every `POST`/`PUT`/`DELETE`/`PATCH`.
3. **XSS Prevention:**
   - Strict `Content-Security-Policy` (`default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none'`) + `X-Content-Type-Options: nosniff`.
   - Frontend renders all untrusted APK fields (package names, DEX strings, URLs, diffs, manifest XML, errors) exclusively via `textContent` / safe DOM constructors—zero `innerHTML`.
4. **Path-Traversal & Symlink Containment:**
   - Input APKs are never modified in place.
   - Uploads sanitize filenames (`Path(name).name`) into isolated `<workspace>/uploads/<id>/`.
   - Artifacts and inline file previews are verified via `Path.resolve()` + `is_relative_to()` against tracked job/session roots (`400`/`403` on escape).

---

## 4. Workbenches & Value-Add Features

1. **Dropzone & Instant Inspector:** Drag-and-drop or local path inspection returning package/SDK metadata, ABIs, native frameworks, Pairip verdict, DEX `035`–`041` container breakdown, `resources.arsc` storage, and `extractNativeLibs` readiness.
2. **Privacy Studio (Scan → Diff Preview → Approve):** Interactive toggle cards (`--sinkhole`, `--trust-user-ca`, `--allow-screenshots`, `--strip-ad-permissions`, `--disable-providers`, `--selective-dex`, `--smali-only`, `--merge-splits`, `--allow-custom-domains`, `--force-unsafe`), live YAML Recipe editor with diagnostics, and syntax-colored unified diff preview before building.
3. **Raw Toolkit Tabs:** Dedicated `Decode`, `Build & Sign`, `Merge Splits`, and `Sign & Verify` workflows with `--unsigned`, custom keystore, ABI filtering, and post-merge `extractNativeLibs` tracking.
4. **Value-Add Productivity Features:**
   - **Live Equivalent CLI Command Bar:** Continuously reflects current UI choices as a copyable `apk-surgeon ...` command.
   - **Toolchain Doctor Drawer:** Live tool versions + 1-click copyable OS install commands (Linux, macOS, Windows, Termux) + APKEditor JAR override.
   - **Real-Time SSE Job Console & Artifact Shelf:** Live step progress, elapsed timer, session size/privacy-score delta cards, and inline **Manifest / Report / Diff Viewer**.
