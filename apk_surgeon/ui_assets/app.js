(() => {
  "use strict";

  const TOKEN = document.querySelector('meta[name="apk-surgeon-token"]')?.getAttribute("content") || "";
  const state = {
    activeTab: "inspect",
    uploadId: null,
    targetLabel: null,
    targetSize: 0,
    activeJobId: null,
    activeEventSource: null,
    timerHandle: null,
    jobStartMs: 0,
    lastDiffText: "",
    lastViewerText: "",
    lastDecodedJobId: null,
    lastDecodedRoot: "",
  };

  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (k === "className") node.className = v;
        else if (k === "hidden") node.hidden = Boolean(v);
        else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2).toLowerCase(), v);
        else if (v !== null && v !== undefined) node.setAttribute(k, String(v));
      }
    }
    for (const child of children) {
      if (child === null || child === undefined) continue;
      node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
    }
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function fmtBytes(n) {
    if (!n && n !== 0) return "-";
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
    return `${(n / (1024 * 1024)).toFixed(2)} MiB`;
  }

  let toastTimer = null;
  function showToast(msg, kind = "info") {
    const toast = document.getElementById("toast");
    toast.textContent = msg;
    toast.className = kind === "error" ? "toast toast-error" : "toast";
    toast.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { toast.hidden = true; }, kind === "error" ? 4200 : 2600);
  }

  function showError(title, detail, { logToConsole = false, toast = true } = {}) {
    const text = String(detail || title || "Unknown error").trim();
    const banner = document.getElementById("error-banner");
    document.getElementById("error-banner-title").textContent = title || "Operation Failed";
    document.getElementById("error-banner-detail").textContent = text;
    banner.hidden = false;
    if (logToConsole) {
      clearInterval(state.timerHandle);
      document.getElementById("job-step").textContent = `${title || "Job"}: Failed`;
      const bar = document.getElementById("job-progress");
      bar.style.width = "100%";
      bar.classList.add("is-error");
      const logBox = document.getElementById("job-logs");
      clear(logBox);
      logBox.appendChild(el("div", { className: "log-line log-err" }, `Error: ${text}`));
    }
    if (toast) showToast(`${title || "Error"}: ${text.split("\n")[0]}`, "error");
  }

  function clearError() {
    document.getElementById("error-banner").hidden = true;
    document.getElementById("error-banner-detail").textContent = "";
  }

  async function apiJson(url, method = "GET", body = null) {
    const opts = { method, headers: { "X-APK-Surgeon-Token": TOKEN } };
    if (body !== null) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const resp = await fetch(url, opts);
    const data = await resp.json().catch(() => ({ ok: false, error: `HTTP ${resp.status}` }));
    if (!resp.ok || data.ok === false) {
      throw new Error(data.error || `Request failed (${resp.status})`);
    }
    return data;
  }

  function currentTargetPayload() {
    const local = document.getElementById("local-path-input").value.trim();
    const jar = document.getElementById("apkeditor-jar-input").value.trim();
    const base = local ? { path: local } : (state.uploadId ? { upload_id: state.uploadId } : {});
    if (jar) base.apkeditor_jar = jar;
    return base;
  }

  function targetCliToken() {
    const local = document.getElementById("local-path-input").value.trim();
    return local || state.targetLabel || "<apk>";
  }

  function updateCliPreview() {
    const apk = targetCliToken();
    const jar = document.getElementById("apkeditor-jar-input").value.trim();
    const jarArgs = jar ? ` --apkeditor-jar ${jar}` : "";
    let cmd = "";
    if (state.activeTab === "inspect") {
      cmd = `apk-surgeon inspect ${apk} --json`;
    } else if (state.activeTab === "clean") {
      const parts = ["apk-surgeon clean", apk];
      const eng = document.getElementById("clean-engine").value;
      if (eng !== "auto") parts.push("--engine", eng);
      const abi = document.getElementById("clean-abi").value;
      if (abi) parts.push("--abi", abi);
      const out = document.getElementById("clean-output").value.trim();
      if (out) parts.push("-o", out);
      if (document.getElementById("opt-sinkhole").checked) parts.push("--sinkhole");
      if (document.getElementById("opt-strip-ad").checked) parts.push("--strip-ad-permissions");
      if (document.getElementById("opt-disable-providers").checked) parts.push("--disable-providers");
      if (document.getElementById("opt-selective-dex").checked) parts.push("--selective-dex");
      if (document.getElementById("opt-smali-only").checked) parts.push("--smali-only");
      if (document.getElementById("opt-trust-ca").checked) parts.push("--trust-user-ca");
      if (document.getElementById("opt-allow-shots").checked) parts.push("--allow-screenshots");
      if (document.getElementById("opt-merge-splits").checked) parts.push("--merge-splits");
      if (document.getElementById("opt-custom-domains").checked) parts.push("--allow-custom-domains");
      if (document.getElementById("opt-force-unsafe").checked) parts.push("--force-unsafe");
      if (document.getElementById("recipe-yaml").value.trim()) parts.push("--recipe", "recipe.yml");
      if (jar) parts.push("--apkeditor-jar", jar);
      cmd = parts.join(" ");
    } else if (state.activeTab === "decode") {
      const eng = document.getElementById("decode-engine").value;
      const out = document.getElementById("decode-output").value.trim() || "app-decoded";
      const flags = [];
      if (eng !== "auto") flags.push(`--engine ${eng}`);
      if (document.getElementById("decode-no-res").checked) flags.push("-r");
      if (document.getElementById("decode-no-src").checked) flags.push("-s");
      if (document.getElementById("decode-force").checked) flags.push("--force");
      cmd = `apk-surgeon decode ${apk} -o ${out}${flags.length ? " " + flags.join(" ") : ""}${jarArgs}`;
    } else if (state.activeTab === "build") {
      const dir = document.getElementById("build-dir").value.trim() || "<dir>";
      const out = document.getElementById("build-output").value.trim() || "rebuilt.apk";
      const eng = document.getElementById("build-engine").value;
      const flags = [];
      if (eng !== "auto") flags.push(`--engine ${eng}`);
      if (document.getElementById("build-unsigned").checked) flags.push("--unsigned");
      if (document.getElementById("build-force").checked) flags.push("--force");
      cmd = `apk-surgeon build ${dir} -o ${out}${flags.length ? " " + flags.join(" ") : ""}${jarArgs}`;
    } else if (state.activeTab === "merge") {
      const abi = document.getElementById("merge-abi").value;
      const out = document.getElementById("merge-output").value.trim() || "merged.apk";
      const flags = [];
      if (abi) flags.push(`--abi ${abi}`);
      if (document.getElementById("merge-unsigned").checked) flags.push("--unsigned");
      if (document.getElementById("merge-force").checked) flags.push("--force");
      cmd = `apk-surgeon merge ${apk} -o ${out}${flags.length ? " " + flags.join(" ") : ""}${jarArgs}`;
    } else {
      const out = document.getElementById("sign-output").value.trim() || "signed.apk";
      const force = document.getElementById("sign-force").checked ? " --force" : "";
      cmd = `apk-surgeon sign ${apk} -o ${out}${force}`;
    }
    document.getElementById("cli-preview").textContent = cmd;
  }

  function switchTab(name) {
    state.activeTab = name;
    document.querySelectorAll(".nav-tab").forEach((btn) => {
      btn.classList.toggle("is-active", btn.getAttribute("data-tab") === name);
    });
    document.querySelectorAll(".tab-panel").forEach((panel) => {
      panel.hidden = panel.id !== `tab-${name}`;
    });
    updateCliPreview();
  }

  function kvRow(k, v, cls = "") {
    return el("div", { className: "kv-row" },
      el("span", { className: "muted" }, k),
      el("span", { className: `kv-val ${cls}`.trim() }, String(v))
    );
  }

  function badgeForVerdict(verdict) {
    if (!verdict) return el("span", { className: "badge badge-neutral" }, "-");
    if (verdict.startsWith("BLOCKED") || verdict === "HIGH RISK") {
      return el("span", { className: "badge badge-danger" }, verdict);
    }
    if (verdict === "CAUTION") return el("span", { className: "badge badge-warn" }, verdict);
    return el("span", { className: "badge badge-safe" }, verdict);
  }

  function renderInspect(data) {
    document.getElementById("inspect-empty").hidden = true;
    document.getElementById("inspect-results").hidden = false;

    const kpis = document.getElementById("inspect-kpis");
    clear(kpis);
    const frameworksText = data.detected_frameworks?.length ? data.detected_frameworks.join(", ") : "Standard JVM/DEX";
    const pairipLabel = data.pairip?.blocked ? "BLOCKED (Pairip)" : "No Pairip VM";
    kpis.append(
      el("div", { className: "kpi" },
        el("div", { className: "kpi-label" }, "Archive & Size"),
        el("div", { className: "kpi-value" }, `${data.archive_type} (${fmtBytes(data.file_size)})`)
      ),
      el("div", { className: "kpi" },
        el("div", { className: "kpi-label" }, "Target / Package"),
        el("div", { className: "kpi-value" }, data.badging?.package || data.file)
      ),
      el("div", { className: "kpi" },
        el("div", { className: "kpi-label" }, "Frameworks"),
        el("div", { className: "kpi-value" }, frameworksText)
      ),
      el("div", { className: "kpi" },
        el("div", { className: "kpi-label" }, "Protection Gate"),
        el("div", { className: "kpi-value" }, badgeForVerdict(pairipLabel))
      )
    );

    const caveat = document.getElementById("inspect-caveat");
    if (data.pairip?.blocked) {
      caveat.hidden = false;
      caveat.textContent = `Pairip VM detected: ${(data.pairip.reasons || []).join("; ")}. Static re-signing is blocked unless --force-unsafe is enabled.`;
    } else if (data.detected_frameworks?.length) {
      caveat.hidden = false;
      caveat.textContent = "Native engine detected (" + frameworksText + "): smali patches cannot reach C++/Dart/JS engine telemetry.";
    } else {
      caveat.hidden = true;
    }

    const storage = document.getElementById("inspect-storage");
    clear(storage);
    const arsc = data.resources_arsc || {};
    const enl = data.extract_native_libs === null ? "unset" : String(data.extract_native_libs);
    storage.append(
      kvRow("resources.arsc", arsc.present ? (arsc.stored ? "ZIP_STORED (OK)" : `${arsc.compress_type} (Needs Fix)`) : "absent"),
      kvRow("Native libs (.so)", `${data.native_libs?.count || 0} (stored: ${data.native_libs?.all_stored})`),
      kvRow("extractNativeLibs", enl),
      kvRow("ABIs", data.abis?.length ? data.abis.join(", ") : "none (Java-only)")
    );

    const badging = document.getElementById("inspect-badging");
    clear(badging);
    const b = data.badging;
    if (b) {
      badging.append(
        kvRow("App Label", b.application_label || "-"),
        kvRow("Package", b.package || "-"),
        kvRow("versionCode / Name", `${b.version_code || "-"} / ${b.version_name || "-"}`),
        kvRow("minSdk / targetSdk", `${b.min_sdk || "-"} / ${b.target_sdk || "-"}`),
        kvRow("Permissions", String(b.permissions_count ?? "-"))
      );
    } else {
      badging.append(kvRow("aapt2 Badging", "aapt2 not available on PATH"));
    }

    const dexBody = document.getElementById("inspect-dex-body");
    clear(dexBody);
    for (const d of data.dex_files || []) {
      dexBody.appendChild(el("tr", null,
        el("td", null, d.name),
        el("td", null, d.version !== null ? `DEX 0${d.version}` : (d.error || "invalid")),
        el("td", null, d.header_size ? `${d.header_size} B` : "-"),
        el("td", null, String(d.container_sections || 1))
      ));
    }

    const splitsCard = document.getElementById("inspect-splits-card");
    const splits = document.getElementById("inspect-splits");
    clear(splits);
    if (data.split_apks?.length) {
      splitsCard.hidden = false;
      for (const s of data.split_apks) splits.appendChild(el("span", { className: "chip" }, s));
    } else {
      splitsCard.hidden = true;
    }
  }

  function renderDiffLines(container, lines) {
    clear(container);
    if (!lines || !lines.length) {
      container.appendChild(el("div", { className: "muted" }, "No file changes planned."));
      return;
    }
    for (const line of lines) {
      let cls = "diff-line";
      if (line.startsWith("+") && !line.startsWith("+++")) cls += " diff-add";
      else if (line.startsWith("-") && !line.startsWith("---")) cls += " diff-del";
      else if (line.startsWith("@@")) cls += " diff-hunk";
      container.appendChild(el("div", { className: cls }, line));
    }
  }

  function renderCleanPreview(data) {
    document.getElementById("clean-preview-box").hidden = false;
    const summary = document.getElementById("preview-summary");
    clear(summary);
    summary.append(
      kvRow("Privacy Score", `${data.privacy_score}/100`),
      kvRow("Safety Verdict", data.safety?.verdict || "-"),
      kvRow("Engine", `${data.engine} (${data.decode_type || "default"})`),
      kvRow("Changed Files", String(data.changed_files?.length || 0)),
      kvRow("Sinkholed URLs", String(data.stats?.sinkholed?.length || 0)),
      kvRow("FLAG_SECURE Fixed", String(data.stats?.screenshots || 0))
    );
    const trackers = document.getElementById("preview-trackers");
    clear(trackers);
    if (!data.trackers?.length) {
      trackers.appendChild(el("div", { className: "muted small" }, "No built-in SDK trackers found."));
    } else {
      for (const t of data.trackers) {
        trackers.appendChild(el("div", { className: "artifact-item" },
          el("div", null,
            el("strong", null, t.name),
            el("div", { className: "muted small" }, `classes: ${t.classes}, hooks: ${t.hooks.length}, components: ${t.components.length}`)
          ),
          el("span", { className: "badge badge-neutral" }, `${(t.evidence || []).length} evidence`)
        ));
      }
    }
    if (data.sinkhole?.candidates?.length) {
      trackers.appendChild(el("div", { className: "small muted" }, `Sinkhole targets (${data.sinkhole.candidates.length}): ${data.sinkhole.candidates.join(", ")}`));
    }
    state.lastDiffText = (data.diff_lines || []).join("\n");
    renderDiffLines(document.getElementById("preview-diff"), data.diff_lines);
  }

  function renderVerify(data) {
    document.getElementById("verify-box").hidden = false;
    const alertBox = document.getElementById("verify-alert");
    const box = document.getElementById("verify-results");
    clear(box);
    const failedRows = (data.apks || []).filter((r) => r.errors?.length);
    if (data.ok === false || failedRows.length) {
      alertBox.hidden = false;
      alertBox.textContent = `Verification FAILED for ${failedRows.length || 1} APK(s). Review errors and scheme breakdown below.`;
    } else {
      alertBox.hidden = true;
    }
    for (const row of data.apks || []) {
      const schemes = Object.entries(row.schemes || {})
        .map(([k, v]) => `${k}:${v === null ? "n/a" : (v ? "OK" : "NO")}`)
        .join("  ");
      box.appendChild(el("div", { className: "card" },
        el("div", { className: "card-head" },
          el("strong", null, row.apk),
          el("span", { className: `badge ${row.errors?.length ? "badge-danger" : "badge-safe"}` }, row.errors?.length ? "FAIL" : "PASS")
        ),
        kvRow("16 KiB Alignment", row.aligned ? "PASS" : "FAIL"),
        kvRow("Schemes", schemes),
        kvRow("Cert SHA-256", (row.certificates_sha256 || []).join(", ") || "none"),
        ...(row.errors || []).map((err) => el("div", { className: "log-err small" }, err))
      ));
    }
  }

  async function loadDecodedBrowser(jobId, rootPath) {
    state.lastDecodedJobId = jobId;
    state.lastDecodedRoot = rootPath;
    document.getElementById("decoded-browser").hidden = false;
    document.getElementById("decoded-root-label").textContent = rootPath;
    const listBox = document.getElementById("decoded-file-list");
    clear(listBox);
    const data = await apiJson(`/api/jobs/${encodeURIComponent(jobId)}/files`);
    for (const rel of data.files) {
      const btn = el("button", {
        type: "button",
        className: "file-btn",
        onClick: async () => {
          listBox.querySelectorAll(".file-btn").forEach((n) => n.classList.remove("is-selected"));
          btn.classList.add("is-selected");
          try {
            const fileData = await apiJson(
              `/api/workspace-file?job_id=${encodeURIComponent(jobId)}&path=${encodeURIComponent(rel)}`
            );
            document.getElementById("decoded-file-content").textContent = fileData.content;
          } catch (err) {
            showError("Could not load file", err.message);
          }
        },
      }, rel);
      listBox.appendChild(btn);
    }
  }

  async function openArtifactViewer(art) {
    const res = await apiJson(`${art.url}?inline=1`);
    document.getElementById("viewer-title").textContent = res.name;
    const body = document.getElementById("viewer-body");
    state.lastViewerText = res.content;
    if (res.name.endsWith(".diff")) {
      renderDiffLines(body, res.content.split("\n"));
    } else {
      clear(body);
      body.textContent = res.content;
    }
    document.getElementById("viewer-modal").hidden = false;
  }

  function renderJob(job, { fromHistory = false } = {}) {
    document.getElementById("job-step").textContent = `${job.type}: ${job.step}`;
    const bar = document.getElementById("job-progress");
    bar.style.width = `${job.progress || 0}%`;
    const isVerifyFail = job.type === "verify" && (job.result?.ok === false || job.summary?.verified_ok === false);
    bar.classList.toggle("is-error", job.status === "error" || isVerifyFail);
    bar.classList.toggle("is-cancelled", job.status === "cancelled");
    const cancelBtn = document.getElementById("btn-cancel-job");
    const active = job.status === "queued" || job.status === "running";
    cancelBtn.hidden = !active;
    if (active && job.id === state.activeJobId) cancelBtn.disabled = false;
    if (job.status === "done" || job.status === "error" || job.status === "cancelled") {
      document.getElementById("job-timer").textContent = `${(job.elapsed_ms / 1000).toFixed(1)}s`;
    }
    const logBox = document.getElementById("job-logs");
    clear(logBox);
    for (const entry of job.logs || []) {
      const isErr = entry.message.startsWith("Error:");
      const isWarn = entry.message.startsWith("Warning:") || entry.message.includes("cancelled");
      const cls = isErr ? "log-line log-err" : (isWarn ? "log-line log-warn" : "log-line");
      logBox.appendChild(el("div", { className: cls }, entry.message));
    }
    logBox.scrollTop = logBox.scrollHeight;

    const artBox = document.getElementById("artifact-list");
    clear(artBox);
    if (!job.artifacts?.length) {
      artBox.appendChild(el("div", { className: "muted small" }, "No file artifacts produced for this job."));
    } else {
      for (const art of job.artifacts) {
        const actions = el("div", { className: "btn-row" });
        if (art.inline) {
          actions.appendChild(el("button", {
            type: "button",
            className: "btn btn-ghost btn-sm",
            onClick: () => openArtifactViewer(art).catch((e) => showError("Artifact preview failed", e.message)),
          }, "View"));
        }
        actions.appendChild(el("a", {
          href: art.url,
          download: art.name,
          className: "btn btn-secondary btn-sm",
        }, "Download"));
        artBox.appendChild(el("div", { className: "artifact-item" },
          el("div", null,
            el("strong", null, art.label),
            el("div", { className: "muted small" }, `${art.name} (${fmtBytes(art.size)})`)
          ),
          actions
        ));
      }
    }

    if (fromHistory) {
      if (job.status === "error") {
        showError(`${job.type} failed`, job.error || "Job failed", { toast: false });
      } else {
        clearError();
        if (job.type === "verify" && job.result) renderVerify(job.result);
        else if (job.result?.verify) renderVerify(job.result.verify);
      }
    }
  }

  async function refreshHistory() {
    const data = await apiJson("/api/jobs");
    const box = document.getElementById("history-list");
    clear(box);
    if (!data.jobs.length) {
      box.appendChild(el("div", { className: "muted small" }, "No jobs run in this session yet."));
      return;
    }
    for (const j of data.jobs.slice(0, 12)) {
      let badgeCls = "badge-warn";
      let badgeText = j.status;
      if (j.status === "error") {
        badgeCls = "badge-danger";
      } else if (j.status === "cancelled") {
        badgeCls = "badge-warn";
      } else if (j.type === "verify" && j.summary?.verified_ok === false) {
        badgeCls = "badge-danger";
        badgeText = "FAIL";
      } else if (j.status === "done") {
        badgeCls = "badge-safe";
      }
      let delta = "";
      if (j.summary?.input_size && j.summary?.output_size) {
        delta = ` (${fmtBytes(j.summary.input_size)} -> ${fmtBytes(j.summary.output_size)})`;
      } else if (j.summary?.privacy_score !== undefined) {
        delta = ` (score ${j.summary.privacy_score}/100)`;
      }
      const cls = `history-item${state.activeJobId === j.id ? " is-selected" : ""}`;
      box.appendChild(el("div", {
        className: cls,
        onClick: () => {
          state.activeJobId = j.id;
          renderJob(j, { fromHistory: true });
          refreshHistory().catch(() => {});
        },
      },
        el("div", null,
          el("strong", null, `${j.type}${delta}`),
          el("div", { className: "muted small" }, `${(j.elapsed_ms / 1000).toFixed(1)}s • ${j.step}`)
        ),
        el("span", { className: `badge ${badgeCls}` }, badgeText)
      ));
    }
  }

  function startJob(type, payload, onDone) {
    clearError();
    if (type === "verify" || type === "sign") {
      document.getElementById("verify-box").hidden = true;
      document.getElementById("verify-alert").hidden = true;
    } else if (type === "clean_preview") {
      document.getElementById("clean-preview-box").hidden = true;
    }
    if (state.activeEventSource) {
      state.activeEventSource.close();
      state.activeEventSource = null;
    }
    clearInterval(state.timerHandle);
    document.getElementById("job-progress").classList.remove("is-error", "is-cancelled");
    state.jobStartMs = Date.now();
    state.timerHandle = setInterval(() => {
      document.getElementById("job-timer").textContent = `${((Date.now() - state.jobStartMs) / 1000).toFixed(1)}s`;
    }, 100);

    apiJson("/api/jobs", "POST", { type, ...payload }).then(({ job }) => {
      state.activeJobId = job.id;
      renderJob(job);
      const es = new EventSource(`/api/jobs/${encodeURIComponent(job.id)}/events`);
      state.activeEventSource = es;
      let settled = false;

      const finishJob = (updated) => {
        if (settled) return;
        settled = true;
        es.close();
        state.activeEventSource = null;
        clearInterval(state.timerHandle);
        renderJob(updated);
        refreshHistory().catch(() => {});
        if (updated.status === "done") {
          if (onDone) onDone(updated);
          if (type === "verify" && updated.result && !updated.result.ok) {
            showToast("Verification FAILED — review diagnostics below", "error");
          }
        } else if (updated.status === "cancelled") {
          showToast(`${type} cancelled`);
        } else if (updated.status === "error") {
          showError(`${type} failed`, updated.error || "Job failed");
        }
      };

      const handleEvent = (ev) => {
        const updated = JSON.parse(ev.data);
        if (updated.status === "done" || updated.status === "error" || updated.status === "cancelled") {
          finishJob(updated);
        } else {
          renderJob(updated);
        }
      };
      es.addEventListener("state", handleEvent);
      es.addEventListener("done", handleEvent);
      es.onerror = () => {
        if (settled) return;
        es.close();
        state.activeEventSource = null;
        apiJson(`/api/jobs/${encodeURIComponent(job.id)}`)
          .then(({ job: latest }) => {
            if (latest.status === "done" || latest.status === "error" || latest.status === "cancelled") {
              finishJob(latest);
            } else {
              renderJob(latest);
              clearInterval(state.timerHandle);
              showError("Live stream interrupted", `Lost event stream while ${type} was ${latest.status}.`);
            }
          })
          .catch((err) => {
            clearInterval(state.timerHandle);
            showError(`${type} connection lost`, err.message, { logToConsole: true });
          });
      };
    }).catch((err) => {
      clearInterval(state.timerHandle);
      document.getElementById("btn-cancel-job").hidden = true;
      showError(`${type} could not start`, err.message, { logToConsole: true });
    });
  }

  async function uploadFile(file) {
    if (!file) return;
    clearError();
    const nameNode = document.getElementById("active-target-name");
    const metaNode = document.getElementById("active-target-meta");
    const prevName = nameNode.textContent;
    const prevMeta = metaNode.textContent;
    nameNode.textContent = `Uploading ${file.name}...`;
    metaNode.textContent = `${fmtBytes(file.size)} — uploading to temporary UI workspace...`;
    try {
      const resp = await fetch("/api/upload", {
        method: "POST",
        headers: {
          "X-APK-Surgeon-Token": TOKEN,
          "X-Filename": file.name,
          "Content-Type": "application/octet-stream",
        },
        body: file,
      });
      const data = await resp.json().catch(() => ({ ok: false, error: `HTTP ${resp.status}` }));
      if (!resp.ok || !data.ok) throw new Error(data.error || "Upload failed");
      state.uploadId = data.upload_id;
      state.targetLabel = data.filename;
      state.targetSize = data.size;
      document.getElementById("local-path-input").value = "";
      nameNode.textContent = data.filename;
      metaNode.textContent = `Uploaded (${fmtBytes(data.size)})`;
      updateCliPreview();
    } catch (err) {
      nameNode.textContent = prevName;
      metaNode.textContent = prevMeta;
      throw err;
    }
    await runQuickInspect();
  }

  async function runQuickInspect() {
    clearError();
    const target = currentTargetPayload();
    if (!target.path && !target.upload_id) {
      showError("No APK target selected", "Upload an APK/bundle or enter a local file path first.");
      return;
    }
    try {
      const data = await apiJson("/api/inspect", "POST", target);
      renderInspect(data);
      switchTab("inspect");
    } catch (err) {
      document.getElementById("inspect-results").hidden = true;
      document.getElementById("inspect-empty").hidden = false;
      showError("Inspect failed", err.message, { logToConsole: true });
    }
  }

  async function loadDoctor() {
    const jar = document.getElementById("apkeditor-jar-input").value.trim();
    const data = jar
      ? await apiJson("/api/doctor", "POST", { apkeditor_jar: jar })
      : await apiJson("/api/doctor");
    document.getElementById("app-version").textContent = `v${data.version}`;
    const missing = data.missing_required.length;
    const dot = document.getElementById("doctor-dot");
    dot.className = `dot ${missing === 0 ? "dot-ok" : "dot-warn"}`;
    document.getElementById("doctor-summary").textContent =
      missing === 0 ? "Toolchain Ready" : `${6 - missing}/6 Tools`;

    const toolsBox = document.getElementById("doctor-tools");
    clear(toolsBox);
    for (const t of data.tools) {
      toolsBox.appendChild(el("div", { className: "artifact-item" },
        el("div", null,
          el("strong", null, t.name),
          el("div", { className: "muted small" }, t.version ? `v${t.version} • ${t.path}` : (t.path || "not on PATH")),
          t.warning ? el("div", { className: "log-err small" }, t.warning) : null
        ),
        el("span", { className: `badge ${t.present ? "badge-safe" : "badge-danger"}` }, t.present ? "OK" : "Missing")
      ));
    }

    const apke = document.getElementById("doctor-apkeditor");
    clear(apke);
    apke.append(
      el("h3", null, "APKEditor (Optional Fallback & Merge)"),
      el("div", { className: "small" }, data.apkeditor.present
        ? `${data.apkeditor.path} (v${data.apkeditor.version || "unknown"})`
        : (data.apkeditor.error || "Missing — set APKEditor JAR input or APK_SURGEON_APKEDITOR_JAR"))
    );

    const guides = document.getElementById("doctor-guides-list");
    clear(guides);
    for (const [osName, cmd] of Object.entries(data.install_guides || {})) {
      guides.appendChild(el("div", { className: "artifact-item" },
        el("div", null,
          el("strong", null, osName.toUpperCase()),
          el("div", { className: "cli-code small" }, cmd)
        ),
        el("button", {
          type: "button",
          className: "btn btn-ghost btn-sm",
          onClick: () => navigator.clipboard?.writeText(cmd).then(() => showToast(`Copied ${osName} command`)),
        }, "Copy")
      ));
    }
  }

  let recipeTimer = null;
  function scheduleRecipeValidation() {
    clearTimeout(recipeTimer);
    recipeTimer = setTimeout(async () => {
      const yaml = document.getElementById("recipe-yaml").value;
      const badge = document.getElementById("recipe-status");
      const fb = document.getElementById("recipe-feedback");
      if (!yaml.trim()) {
        badge.className = "badge badge-neutral";
        badge.textContent = "Empty";
        fb.textContent = "";
        return;
      }
      try {
        const res = await apiJson("/api/recipe/validate", "POST", {
          yaml,
          allow_custom_domains: document.getElementById("opt-custom-domains").checked,
        });
        badge.className = "badge badge-safe";
        badge.textContent = "Valid YAML";
        const s = res.summary;
        fb.textContent = `Prefixes: ${s.package_prefixes}, Hooks: ${s.methods}, Components: ${s.disable_components}, Domains: ${s.sinkhole_domains.length}`;
      } catch (err) {
        badge.className = "badge badge-danger";
        badge.textContent = "Invalid";
        fb.textContent = err.message;
      }
    }, 250);
  }

  function cleanPayload() {
    return {
      ...currentTargetPayload(),
      engine: document.getElementById("clean-engine").value,
      abi: document.getElementById("clean-abi").value || null,
      output: document.getElementById("clean-output").value.trim() || null,
      sinkhole: document.getElementById("opt-sinkhole").checked,
      strip_ad_permissions: document.getElementById("opt-strip-ad").checked,
      disable_providers: document.getElementById("opt-disable-providers").checked,
      selective_dex: document.getElementById("opt-selective-dex").checked,
      smali_only: document.getElementById("opt-smali-only").checked,
      trust_user_ca: document.getElementById("opt-trust-ca").checked,
      allow_screenshots: document.getElementById("opt-allow-shots").checked,
      merge_splits: document.getElementById("opt-merge-splits").checked,
      allow_custom_domains: document.getElementById("opt-custom-domains").checked,
      force_unsafe: document.getElementById("opt-force-unsafe").checked,
      recipe_yaml: document.getElementById("recipe-yaml").value,
    };
  }

  // Event bindings
  document.querySelectorAll(".nav-tab").forEach((btn) => {
    btn.addEventListener("click", () => switchTab(btn.getAttribute("data-tab")));
  });

  const dz = document.getElementById("dropzone");
  const picker = document.getElementById("file-picker");
  document.getElementById("btn-browse").addEventListener("click", (e) => { e.stopPropagation(); picker.click(); });
  dz.addEventListener("click", () => picker.click());
  dz.addEventListener("dragover", (e) => { e.preventDefault(); dz.classList.add("is-drag"); });
  dz.addEventListener("dragleave", () => dz.classList.remove("is-drag"));
  dz.addEventListener("drop", (e) => {
    e.preventDefault();
    dz.classList.remove("is-drag");
    const file = e.dataTransfer?.files?.[0];
    if (file) uploadFile(file).catch((err) => showError("Upload failed", err.message, { logToConsole: true }));
  });
  picker.addEventListener("change", () => {
    const file = picker.files?.[0];
    if (file) uploadFile(file).catch((err) => showError("Upload failed", err.message, { logToConsole: true }));
  });

  document.getElementById("btn-dismiss-error").addEventListener("click", clearError);
  document.getElementById("btn-cancel-job").addEventListener("click", () => {
    const jid = state.activeJobId;
    if (!jid) return;
    const btn = document.getElementById("btn-cancel-job");
    btn.disabled = true;
    apiJson(`/api/jobs/${encodeURIComponent(jid)}/cancel`, "POST", {})
      .then((res) => {
        if (res.job) renderJob(res.job);
      })
      .catch((err) => {
        btn.disabled = false;
        showError("Cancel failed", err.message, { logToConsole: true });
      });
  });
  document.getElementById("btn-quick-inspect").addEventListener("click", () => runQuickInspect());
  document.getElementById("btn-inspect-to-clean").addEventListener("click", () => switchTab("clean"));
  document.getElementById("btn-inspect-to-decode").addEventListener("click", () => switchTab("decode"));
  document.getElementById("btn-copy-cli").addEventListener("click", () => {
    navigator.clipboard?.writeText(document.getElementById("cli-preview").textContent)
      .then(() => showToast("CLI command copied"));
  });

  document.getElementById("btn-clean-preview").addEventListener("click", () => {
    startJob("clean_preview", cleanPayload(), (job) => renderCleanPreview(job.result));
  });
  document.getElementById("btn-clean-apply").addEventListener("click", () => {
    startJob("clean", cleanPayload(), (job) => {
      if (job.result?.noop) showToast("No allowlisted changes needed.");
      else showToast("Clean APK built & signed.");
    });
  });

  document.getElementById("btn-recipe-sample").addEventListener("click", () => {
    document.getElementById("recipe-yaml").value =
      "version: 1\npackage_prefixes:\n  - com.example.tracker\nmethods:\n  - Lcom/example/Tracker;->send()V\nsinkhole_domains:\n  - api.segment.io\n";
    scheduleRecipeValidation();
    updateCliPreview();
  });
  document.getElementById("btn-recipe-clear").addEventListener("click", () => {
    document.getElementById("recipe-yaml").value = "";
    scheduleRecipeValidation();
    updateCliPreview();
  });
  document.getElementById("recipe-yaml").addEventListener("input", () => {
    scheduleRecipeValidation();
    updateCliPreview();
  });
  document.getElementById("opt-custom-domains").addEventListener("change", scheduleRecipeValidation);
  document.getElementById("btn-copy-diff").addEventListener("click", () => {
    navigator.clipboard?.writeText(state.lastDiffText).then(() => showToast("Diff copied"));
  });

  document.getElementById("btn-run-decode").addEventListener("click", () => {
    const payload = {
      ...currentTargetPayload(),
      engine: document.getElementById("decode-engine").value,
      output: document.getElementById("decode-output").value.trim() || null,
      no_res: document.getElementById("decode-no-res").checked,
      no_src: document.getElementById("decode-no-src").checked,
      force: document.getElementById("decode-force").checked,
    };
    startJob("decode", payload, (job) => {
      loadDecodedBrowser(job.id, job.result.output).catch((err) => showError("Decoded file browser failed", err.message));
    });
  });
  document.getElementById("btn-send-to-build").addEventListener("click", () => {
    if (state.lastDecodedRoot) document.getElementById("build-dir").value = state.lastDecodedRoot;
    switchTab("build");
  });

  document.getElementById("btn-detect-engine").addEventListener("click", async () => {
    clearError();
    const badge = document.getElementById("detected-engine-badge");
    try {
      const dir = document.getElementById("build-dir").value.trim();
      const res = await apiJson("/api/detect-engine", "POST", { directory: dir });
      badge.textContent = `detected: ${res.engine}`;
      badge.className = "badge badge-safe";
    } catch (err) {
      badge.textContent = "detection failed";
      badge.className = "badge badge-danger";
      showError("Engine detection failed", err.message, { logToConsole: true });
    }
  });

  document.getElementById("btn-run-build").addEventListener("click", () => {
    startJob("build", {
      directory: document.getElementById("build-dir").value.trim(),
      output: document.getElementById("build-output").value.trim() || null,
      engine: document.getElementById("build-engine").value,
      apkeditor_jar: document.getElementById("apkeditor-jar-input").value.trim() || null,
      unsigned: document.getElementById("build-unsigned").checked,
      force: document.getElementById("build-force").checked,
      keystore: document.getElementById("build-ks").value.trim() || null,
      ks_alias: document.getElementById("build-ks-alias").value.trim() || null,
      ks_pass: document.getElementById("build-ks-pass").value || null,
    });
  });

  document.getElementById("btn-run-merge").addEventListener("click", () => {
    startJob("merge", {
      ...currentTargetPayload(),
      abi: document.getElementById("merge-abi").value || null,
      output: document.getElementById("merge-output").value.trim() || null,
      unsigned: document.getElementById("merge-unsigned").checked,
      force: document.getElementById("merge-force").checked,
    });
  });

  document.getElementById("btn-run-verify").addEventListener("click", () => {
    startJob("verify", currentTargetPayload(), (job) => renderVerify(job.result));
  });

  document.getElementById("btn-run-sign").addEventListener("click", () => {
    startJob("sign", {
      ...currentTargetPayload(),
      output: document.getElementById("sign-output").value.trim() || null,
      force: document.getElementById("sign-force").checked,
      keystore: document.getElementById("sign-ks").value.trim() || null,
      ks_alias: document.getElementById("sign-ks-alias").value.trim() || null,
      ks_pass: document.getElementById("sign-ks-pass").value || null,
    }, (job) => {
      if (job.result?.verify) renderVerify(job.result.verify);
    });
  });

  document.getElementById("btn-doctor").addEventListener("click", () => {
    loadDoctor().catch((e) => showError("Toolchain check failed", e.message));
    document.getElementById("doctor-drawer").hidden = false;
  });
  document.getElementById("btn-close-doctor").addEventListener("click", () => {
    document.getElementById("doctor-drawer").hidden = true;
  });
  document.getElementById("doctor-backdrop").addEventListener("click", () => {
    document.getElementById("doctor-drawer").hidden = true;
  });

  document.getElementById("btn-close-viewer").addEventListener("click", () => {
    document.getElementById("viewer-modal").hidden = true;
  });
  document.getElementById("viewer-backdrop").addEventListener("click", () => {
    document.getElementById("viewer-modal").hidden = true;
  });
  document.getElementById("btn-copy-viewer").addEventListener("click", () => {
    navigator.clipboard?.writeText(state.lastViewerText).then(() => showToast("Viewer text copied"));
  });

  document.querySelectorAll("input, select").forEach((ctrl) => {
    ctrl.addEventListener("input", updateCliPreview);
    ctrl.addEventListener("change", updateCliPreview);
  });

  updateCliPreview();
  loadDoctor().catch((err) => {
    document.getElementById("doctor-summary").textContent = "Doctor Error";
    showError("Toolchain doctor failed", err.message);
  });
  refreshHistory().catch((err) => showError("Failed loading session history", err.message, { toast: false }));
})();
