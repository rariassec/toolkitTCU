"use strict";

const PAGE_META = {
  dashboard: ["Panel principal", "Resumen general de la sesión de seguridad"],
  web: ["Análisis Web", "Evaluación de seguridad de sitios web"],
  network: ["Análisis de Red", "Escaneo de puertos, servicios, DNS y riesgo"],
  integrity: ["Integridad de Archivos (FIM)", "Vigilancia de cambios en archivos"],
  unified: ["Reporte unificado", "Hallazgos consolidados de los tres módulos"],
  keys: ["API Keys", "Credenciales de VirusTotal y NVD"],
  reports: ["Reportes", "Archivos generados por el toolkit"],
};

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (v) => String(v ?? "").replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

async function api(path, method = "GET", payload) {
  const opts = { method, headers: { "Content-Type": "application/json" } };
  if (payload !== undefined) opts.body = JSON.stringify(payload);
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok || data.ok === false) throw new Error(data.error || `Error ${res.status}`);
  return data.data !== undefined ? data.data : data;
}

function toast(msg, type = "") {
  const box = $("#toasts");
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.textContent = msg;
  box.appendChild(el);
  setTimeout(() => { el.style.opacity = "0"; setTimeout(() => el.remove(), 300); }, 4200);
}

function sevBadge(s) { return `<span class="badge sev-${esc(s)}">${esc(s)}</span>`; }

function busy(btn, on) {
  if (!btn) return;
  if (on) {
    btn.dataset.label = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner"></span> Ejecutando…`;
  } else {
    btn.disabled = false;
    if (btn.dataset.label) btn.innerHTML = btn.dataset.label;
  }
}

function table(headers, rows, mapRow) {
  if (!rows || !rows.length) return `<p class="empty">Sin resultados.</p>`;
  const head = headers.map((h) => `<th>${esc(h)}</th>`).join("");
  const body = rows.map((r) => `<tr>${mapRow(r)}</tr>`).join("");
  return `<div class="table-wrap"><table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
}

async function runJob(startPromise, { btn, onDone, label } = {}) {
  busy(btn, true);
  try {
    const job = await startPromise;
    if (label) toast(`Tarea iniciada: ${label}`, "");
    const result = await pollJob(job.id);
    busy(btn, false);
    if (onDone) onDone(result);
  } catch (e) {
    busy(btn, false);
    toast(e.message, "err");
  }
}

function pollJob(id) {
  return new Promise((resolve, reject) => {
    const tick = async () => {
      try {
        const j = await api(`/api/jobs/${id}`);
        if (j.status === "done") return resolve(j.result);
        if (j.status === "error") return reject(new Error(j.error || "La tarea falló."));
        setTimeout(tick, 1200);
      } catch (e) { reject(e); }
    };
    tick();
  });
}

function goto(page) {
  $$(".nav button").forEach((b) => b.classList.toggle("active", b.dataset.page === page));
  $$(".page").forEach((p) => p.classList.remove("active"));
  const sec = $(`#page-${page}`);
  if (sec) sec.classList.add("active");
  const [title, crumb] = PAGE_META[page] || ["", ""];
  $("#pageTitle").textContent = title;
  $("#pageCrumb").textContent = crumb;
  if (page === "dashboard" || page === "unified") loadUnified();
  if (page === "integrity") loadIntegrityStatus();
  if (page === "network") loadNetState();
  if (page === "keys") loadKeys();
  if (page === "reports") loadReports();
  window.scrollTo(0, 0);
}

document.addEventListener("click", (e) => {
  const nav = e.target.closest(".nav button");
  if (nav) return goto(nav.dataset.page);
  const g = e.target.closest("[data-goto]");
  if (g) return goto(g.dataset.goto);
});

$("#refreshBtn").addEventListener("click", () => {
  const active = $$(".nav button").find((b) => b.classList.contains("active"));
  if (active) goto(active.dataset.page);
});

async function initWebScanners() {
  try {
    const list = await api("/api/web/scanners");
    $("#webScanners").innerHTML = list.map((s) =>
      `<label class="check"><input type="checkbox" class="webScan" value="${esc(s.id)}" checked> ${esc(s.name)}</label>`
    ).join("");
  } catch (e) {}
}

$("#webRunBtn").addEventListener("click", () => {
  const url = $("#webUrl").value.trim();
  if (!url) return toast("Indique una URL.", "err");
  const scanners = $$(".webScan").filter((c) => c.checked).map((c) => c.value);
  const payload = {
    url, scanners,
    timeout: +$("#webTimeout").value || 15,
    max_documents: +$("#webMaxDocs").value || 10,
  };
  $("#webResult").innerHTML = `<div class="card"><p class="empty"><span class="spinner" style="border-color:#ddd;border-top-color:var(--purple)"></span> Analizando ${esc(url)}…</p></div>`;
  runJob(api("/api/web/scan", "POST", payload), {
    btn: $("#webRunBtn"), label: "análisis web",
    onDone: renderWebReport,
  });
});

function renderWebReport(report) {
  const sum = report.executive_summary || {};
  const counts = sum.severity_count || {};
  let html = `<div class="card"><div class="card-head"><h2>Resultado · ${esc(report.metadata?.domain || "")}</h2>
    <span class="pill">${esc(report.metadata?.duration_seconds ?? "?")}s</span></div>
    <div class="grid cols-4" style="margin-bottom:10px">
      <div class="stat good"><div class="label">Puntaje</div><div class="value">${esc(sum.global_score ?? 0)}<small>/100</small></div></div>
      <div class="stat"><div class="label">Hallazgos</div><div class="value">${esc(sum.total_findings ?? 0)}</div></div>
      <div class="stat bad"><div class="label">Críticos/Altos</div><div class="value">${(counts.CRITICAL||0)+(counts.HIGH||0)}</div></div>
      <div class="stat accent"><div class="label">Medios/Bajos</div><div class="value">${(counts.MEDIUM||0)+(counts.LOW||0)}</div></div>
    </div></div>`;

  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  for (const [sid, sc] of Object.entries(report.scanners || {})) {
    const findings = (sc.findings || []).slice().sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
    html += `<div class="card"><div class="card-head"><h2>${esc(sc.scanner || sid)}</h2>
      <span class="pill ${sc.status === 'completed' ? 'green' : sc.status === 'failed' ? 'red' : 'amber'}">${esc(sc.status)}</span></div>`;
    if (!findings.length) html += `<p class="empty">Sin hallazgos.</p>`;
    else findings.forEach((f) => {
      html += `<div class="finding s-${esc(f.severity)}">
        <div class="ftitle">${sevBadge(f.severity)} ${esc(f.title)}</div>
        <div class="fdesc">${esc(f.accessible_description || f.technical_description || "")}</div>
        ${f.recommendation ? `<div class="frec">↪ ${esc(f.recommendation)}</div>` : ""}</div>`;
    });
    html += `</div>`;
  }
  $("#webResult").innerHTML = html;
  toast("Análisis web completado.", "ok");
  loadUnified();
}

async function loadNetState() {
  try {
    const s = await api("/api/network/state");
    $("#netState").innerHTML =
      `<span class="pill">TCP ${s.tcp}</span><span class="pill">UDP ${s.udp}</span>
       <span class="pill">CVE ${s.vulnerabilities}</span><span class="pill">DNS ${s.dns}</span>
       <span class="pill">Conex. ${s.suspicious_connections}</span>
       <span class="pill ${s.risk >= 7 ? 'red' : s.risk >= 4 ? 'amber' : 'green'}">Riesgo ${s.risk}/10</span>`;
  } catch (e) {}
}

function netTarget() {
  const t = $("#netTarget").value.trim();
  if (!t) { toast("Indique un objetivo de red.", "err"); throw new Error("sin objetivo"); }
  return t;
}

$("#netResolveBtn").addEventListener("click", async () => {
  try {
    const r = await api("/api/network/resolve", "POST", { target: $("#netTarget").value });
    const info = $("#netTargetInfo");
    info.style.display = "block";
    info.innerHTML = `<b>✔ Objetivo válido.</b> Escaneo sobre <b>${esc(r.scan_target)}</b>${r.info ? ` — ${esc(r.info)}` : ""}`;
  } catch (e) {
    const info = $("#netTargetInfo");
    info.style.display = "block";
    info.innerHTML = `<span style="color:var(--critical)">✖ ${esc(e.message)}</span>`;
  }
});

function renderPorts(title, res) {
  const html = `<div class="card"><div class="card-head"><h2>${esc(title)}</h2>
    <span class="pill">${res.count} puertos · ${esc(res.ports)}</span></div>
    ${table(["IP", "Puerto", "Protocolo", "Estado", "Servicio", "Versión"], res.rows, (r) =>
      `<td class="mono">${esc(r.ip)}</td><td>${esc(r.port)}</td><td>${esc(r.protocol)}</td>
       <td>${esc(r.state)}</td><td>${esc(r.service)}</td><td>${esc(r.version)}</td>`)}</div>`;
  $("#netResult").innerHTML = html;
  loadNetState();
}

$("#netTcpBtn").addEventListener("click", () => {
  try { const t = netTarget();
    runJob(api("/api/network/tcp", "POST", { target: t, depth: $("#netDepth").value }),
      { btn: $("#netTcpBtn"), label: "escaneo TCP",
        onDone: (r) => { renderPorts("Escaneo TCP", r); toast(`TCP: ${r.count} puertos.`, "ok"); } });
  } catch (e) {}
});

$("#netUdpBtn").addEventListener("click", () => {
  try { const t = netTarget();
    runJob(api("/api/network/udp", "POST", { target: t, depth: $("#netDepth").value }),
      { btn: $("#netUdpBtn"), label: "escaneo UDP",
        onDone: (r) => { renderPorts("Escaneo UDP", r); toast(`UDP: ${r.count} puertos.`, "ok"); } });
  } catch (e) {}
});

$("#netCustomBtn").addEventListener("click", () => {
  try { const t = netTarget();
    const options = {
      technique: $("#cuTechnique").value,
      service_detection: $("#cuSv").checked, os_detection: $("#cuOs").checked,
      skip_ping: $("#cuPn").checked, no_dns: $("#cuN").checked,
      timing: $("#cuTiming").value, scripts: $("#cuScripts").value, extra: $("#cuExtra").value,
    };
    runJob(api("/api/network/custom", "POST", { target: t, ports: $("#cuPorts").value || "1-1024", options }),
      { btn: $("#netCustomBtn"), label: "escaneo personalizado",
        onDone: (r) => { renderPorts("Escaneo personalizado", r); toast(`Escaneo: ${r.count} puertos.`, "ok"); } });
  } catch (e) {}
});

$("#netVulnBtn").addEventListener("click", () => {
  runJob(api("/api/network/vulnerabilities", "POST", { protocol: $("#netVulnProto").value }),
    { btn: $("#netVulnBtn"), label: "detección de CVEs",
      onDone: (r) => {
        const html = `<div class="card"><div class="card-head"><h2>Servicios vulnerables</h2>
          <span class="pill ${r.count ? 'red' : 'green'}">${r.count} CVE · ${r.services_analyzed} servicios</span></div>
          ${table(["IP", "Puerto", "Servicio", "Versión", "CVE", "Severidad", "CVSS"], r.rows, (v) =>
            `<td class="mono">${esc(v.ip)}</td><td>${esc(v.port)}</td><td>${esc(v.service)}</td>
             <td>${esc(v.version)}</td><td class="mono">${esc(v.cve)}</td>
             <td>${sevBadge((v.severity||'INFO').toUpperCase())}</td><td>${esc(v.score)}</td>`)}</div>`;
        $("#netResult").innerHTML = html;
        toast(`${r.count} vulnerabilidades.`, r.count ? "err" : "ok");
        loadNetState();
      } });
});

$("#dnsBtn").addEventListener("click", () => {
  const val = $("#dnsValue").value.trim();
  if (!val) return toast("Indique un dominio o IP.", "err");
  runJob(api("/api/network/dns", "POST", { value: val, mode: $("#dnsMode").value }),
    { btn: $("#dnsBtn"), label: "análisis DNS",
      onDone: (r) => {
        const html = `<div class="card"><h2>Análisis DNS</h2>
          ${table(["Tipo", "Valor", "Resultado", "IP maliciosa", "Sospechoso"], r.rows, (d) =>
            `<td>${esc(d.type)}</td><td class="mono">${esc(d.value)}</td><td class="mono">${esc(d.resolved)}</td>
             <td>${esc(d.ip_malicious)}</td><td>${esc(d.suspicious)}</td>`)}</div>`;
        $("#netResult").innerHTML = html;
        toast("Análisis DNS completado.", "ok");
        loadNetState();
      } });
});

$("#suspBtn").addEventListener("click", () => {
  const dur = +$("#suspDur").value || 60;
  toast(`Capturando tráfico durante ${dur}s…`, "");
  runJob(api("/api/network/suspicious", "POST", { duration_seconds: dur, analysis_type: $("#suspType").value }),
    { btn: $("#suspBtn"), label: "monitoreo de conexiones",
      onDone: (r) => {
        const html = `<div class="card"><div class="card-head"><h2>Conexiones sospechosas</h2>
          <span class="pill">${r.total} conex. · ${r.suspicious} sospechosas · ${r.high_risk} alto riesgo</span></div>
          ${table(["Origen", "Destino", "Puerto", "Proto", "País", "Maliciosa", "Riesgo", "Sospechosa"], r.rows, (c) =>
            `<td class="mono">${esc(c.src_ip)}</td><td class="mono">${esc(c.dst_ip)}</td><td>${esc(c.port)}</td>
             <td>${esc(c.protocol)}</td><td>${esc(c.country)}</td><td>${esc(c.malicious)}</td>
             <td>${sevBadge(({ALTO:'HIGH',MEDIO:'MEDIUM',BAJO:'LOW'})[c.risk]||'INFO')}</td><td>${esc(c.suspicious)}</td>`)}</div>`;
        $("#netResult").innerHTML = html;
        toast(`${r.suspicious} conexiones sospechosas.`, r.suspicious ? "err" : "ok");
        loadNetState();
      } });
});

$("#riskBtn").addEventListener("click", async () => {
  busy($("#riskBtn"), true);
  try {
    const r = await api("/api/network/risk");
    const pct = Math.round((r.score / 10) * 100);
    const col = r.score >= 7 ? "var(--critical)" : r.score >= 4 ? "var(--high)" : "var(--ok)";
    const m = r.matrix || {};
    let top = table(["CVE", "Severidad", "CVSS", "Impacto", "Servicio", "Puerto"], r.top, (v) =>
      `<td class="mono">${esc(v.cve)}</td><td>${esc(v.severity)}</td><td>${esc(v.score)}</td>
       <td>${esc(v.impact)}</td><td>${esc(v.service)}</td><td>${esc(v.port)}</td>`);
    $("#riskResult").innerHTML = `
      <div class="gauge" style="margin-bottom:18px">
        <div class="ring" style="--val:${pct};--col:${col}"><div class="num">${esc(r.score)}<small>/10</small></div></div>
        <div><div style="font-size:20px;font-weight:800;color:var(--navy)">${esc(r.level)}</div>
        <div class="muted">${esc(r.total_vulnerabilities)} vulnerabilidades evaluadas</div>
        <div class="tag-row" style="margin-top:10px">
          <span class="badge sev-CRITICAL">Crítico ${m.CRITICO||0}</span>
          <span class="badge sev-HIGH">Alto ${m.ALTO||0}</span>
          <span class="badge sev-MEDIUM">Medio ${m.MEDIO||0}</span>
          <span class="badge sev-LOW">Bajo ${m.BAJO||0}</span></div></div>
      </div><h3>Top vulnerabilidades</h3>${top}`;
    loadNetState();
  } catch (e) { $("#riskResult").innerHTML = `<p class="empty">${esc(e.message)}</p>`; }
  busy($("#riskBtn"), false);
});

$("#netReportBtn").addEventListener("click", async () => {
  busy($("#netReportBtn"), true);
  try {
    const r = await api("/api/network/report", "POST", {});
    toast(`Reporte generado: ${r.pdf}`, "ok");
    loadReports();
  } catch (e) { toast(e.message, "err"); }
  busy($("#netReportBtn"), false);
});

async function loadIntegrityStatus() {
  try {
    const s = await api("/api/integrity/status");
    $("#intMon").textContent = s.monitored_files;
    $("#intChg").textContent = s.detected_changes;
    $("#intLast").textContent = `${s.last_scan_date} ${s.last_scan_time}`;
    const st = $("#intState"); st.textContent = s.system_state;
    const tile = $("#intStateTile");
    tile.className = "stat " + (s.system_state === "Seguro" ? "good" : "bad");
    loadIntegrityConfig();
    loadMonitorStatus();
  } catch (e) { toast("Integridad: " + e.message, "err"); }
}

async function loadMonitorStatus() {
  try {
    const m = await api("/api/integrity/monitor");
    const badge = $("#intMonBadge");
    badge.textContent = m.running ? "activo" : "detenido";
    badge.className = "pill " + (m.running ? "green" : "amber");
    $("#intMonStartBtn").style.display = m.running ? "none" : "";
    $("#intMonStopBtn").style.display = m.running ? "" : "none";

    const watched = m.watched || [];
    $("#intWatched").innerHTML = watched.length
      ? watched.map((w) => `<span class="pill ${w.exists ? 'green' : 'red'}" title="${w.exists ? 'existe' : 'no existe'}">${esc(w.path)}</span>`).join("")
      : `<span class="muted">Sin carpetas configuradas.</span>`;

    $("#intMailStatus").innerHTML = m.email_enabled && m.email_configured
      ? `<span class="pill green">habilitadas</span>`
      : m.email_configured
        ? `<span class="pill amber">configuradas, deshabilitadas</span>`
        : `<span class="pill amber">no configuradas</span>`;
  } catch (e) {}
}

$("#intMonStartBtn").addEventListener("click", async () => {
  busy($("#intMonStartBtn"), true);
  try {
    await api("/api/integrity/monitor/start", "POST", {});
    toast("Monitoreo en tiempo real iniciado.", "ok");
    loadMonitorStatus(); loadIntegrityStatus();
  } catch (e) { toast(e.message, "err"); }
  busy($("#intMonStartBtn"), false);
});

$("#intMonStopBtn").addEventListener("click", async () => {
  busy($("#intMonStopBtn"), true);
  try {
    await api("/api/integrity/monitor/stop", "POST", {});
    toast("Monitoreo detenido.", "");
    loadMonitorStatus();
  } catch (e) { toast(e.message, "err"); }
  busy($("#intMonStopBtn"), false);
});

async function loadIntegrityConfig() {
  try {
    const c = await api("/api/integrity/config");
    $("#intCfgPaths").value = (c.paths || []).join("\n");
    $("#intCfgAlgo").value = c.algorithm || "sha256";
    $("#intCfgInt").value = c.scan_interval || 10;
    $("#intCfgRec").checked = !!c.recursive;
  } catch (e) {}
}

$("#intStoreBtn").addEventListener("click", async () => {
  busy($("#intStoreBtn"), true);
  try {
    const r = await api("/api/integrity/store", "POST", { path: $("#intPath").value, algorithm: $("#intAlgo").value });
    toast(r.message, r.stored ? "ok" : "");
    loadIntegrityStatus();
  } catch (e) { toast(e.message, "err"); }
  busy($("#intStoreBtn"), false);
});

$("#intDetectBtn").addEventListener("click", () => {
  const options = {
    subdirectories: $("#intSub").checked, hidden_files: $("#intHidden").checked,
    deleted_files: $("#intDeleted").checked, automatic_report: $("#intAutoRep").checked,
    extensions: $("#intExt").value, max_size: $("#intSize").value,
  };
  runJob(api("/api/integrity/detect", "POST", { path: $("#intDetPath").value, options }),
    { btn: $("#intDetectBtn"), label: "detección manual",
      onDone: (r) => {
        toast(r.message, r.outcome === "VERIFIED" ? "ok" : "err");
        loadIntegrityStatus(); loadIntegrityEvents();
      } });
});

async function loadIntegrityEvents() {
  try {
    const evs = await api("/api/integrity/events");
    if (!evs.length) { $("#intEvents").innerHTML = `<p class="empty">Sin eventos registrados.</p>`; return; }
    $("#intEvents").innerHTML = table(["Evento", "Severidad", "Archivo", "Fecha"], evs, (e) =>
      `<td>${esc(e.event_type)}</td><td>${sevBadge((e.severity||'INFO').toUpperCase())}</td>
       <td class="mono">${esc(e.file_path)}</td><td>${esc(e.timestamp)}</td>`);
  } catch (e) { toast(e.message, "err"); }
}
$("#intEventsBtn").addEventListener("click", loadIntegrityEvents);

$("#intGraphBtn").addEventListener("click", async () => {
  busy($("#intGraphBtn"), true);
  try {
    const g = await api("/api/integrity/graphs", "POST", {});
    const imgs = [["Cambios (7 días)", g.changes_7d], ["Extensiones afectadas", g.extensions], ["Tendencia (30 días)", g.tendency_30d]];
    $("#intGraphs").innerHTML = imgs.map(([t, u]) =>
      u ? `<div><div class="muted" style="margin-bottom:6px">${esc(t)}</div><img src="${esc(u)}?t=${Date.now()}" alt="${esc(t)}"></div>`
        : `<div><div class="muted">${esc(t)}</div><p class="empty">Sin datos.</p></div>`).join("");
    toast("Gráficos generados.", "ok");
  } catch (e) { toast(e.message, "err"); }
  busy($("#intGraphBtn"), false);
});

$("#intRepBtn").addEventListener("click", async () => {
  busy($("#intRepBtn"), true);
  try {
    const r = await api("/api/integrity/report", "POST", {});
    toast(`Reporte generado: ${r.pdf}`, "ok");
    loadReports();
  } catch (e) { toast(e.message, "err"); }
  busy($("#intRepBtn"), false);
});

$("#intCfgBtn").addEventListener("click", async () => {
  busy($("#intCfgBtn"), true);
  try {
    const paths = $("#intCfgPaths").value.split("\n").map((p) => p.trim()).filter(Boolean);
    const r = await api("/api/integrity/config", "POST", {
      paths, recursive: $("#intCfgRec").checked,
      algorithm: $("#intCfgAlgo").value, scan_interval: +$("#intCfgInt").value || 10,
    });
    const m = r.monitoring || {};
    if (m.was_running && m.restarted) toast("Configuración guardada. Monitoreo reiniciado automáticamente.", "ok");
    else if (m.was_running) toast("Configuración guardada, pero el monitoreo no pudo reiniciarse: " + (m.restart_error || ""), "err");
    else toast("Configuración guardada.", "ok");
    loadMonitorStatus();
  } catch (e) { toast(e.message, "err"); }
  busy($("#intCfgBtn"), false);
});

$("#mailBtn").addEventListener("click", async () => {
  busy($("#mailBtn"), true);
  try {
    const r = await api("/api/integrity/email", "POST",
      { sender: $("#mailFrom").value, password: $("#mailPass").value, receiver: $("#mailTo").value });
    toast(r.message, "ok");
    $("#mailPass").value = "";
    loadMonitorStatus();
  } catch (e) { toast(e.message, "err"); }
  busy($("#mailBtn"), false);
});

async function loadUnified() {
  try {
    const d = await api("/api/unified");
    const sum = d.report.executive_summary || {};
    const counts = sum.severity_count || {};
    const mods = sum.modules_run || [];

    $("#kpiFindings").textContent = sum.total_findings ?? 0;
    $("#kpiCrit").textContent = (counts.CRITICAL || 0) + (counts.HIGH || 0);
    $("#kpiScore").innerHTML = `${sum.global_score ?? 0}<small>/100</small>`;
    $("#kpiModules").textContent = mods.length;

    const sevTags = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((s) =>
      `<span class="badge sev-${s}">${s} ${counts[s] || 0}</span>`).join("");
    $("#dashSeverity").innerHTML = (sum.total_findings ? sevTags : `<span class="muted">Sin datos todavía. Ejecute algún análisis.</span>`);

    $("#uTotal").textContent = sum.total_findings ?? 0;
    $("#uCrit").textContent = (counts.CRITICAL || 0) + (counts.HIGH || 0);
    $("#uScore").innerHTML = `${sum.global_score ?? 0}<small>/100</small>`;
    $("#uMods").textContent = mods.length ? mods.join(", ") : "ninguno";
    $("#uSeverity").innerHTML = sevTags;

    const fs = d.findings || [];
    $("#uFindings").innerHTML = fs.length ? fs.map((f) =>
      `<div class="finding s-${esc(f.severity)}">
        <div class="ftitle">${sevBadge(f.severity)} <span class="pill">${esc(f.module)}</span> ${esc(f.title)}</div>
        <div class="fdesc">${esc(f.description)}</div>
        ${f.recommendation ? `<div class="frec">↪ ${esc(f.recommendation)}</div>` : ""}</div>`).join("")
      : `<p class="empty">No hay hallazgos consolidados. Ejecute análisis en los módulos.</p>`;
  } catch (e) {}
}

$("#uniRefreshBtn").addEventListener("click", loadUnified);
$("#uniSaveBtn").addEventListener("click", async () => {
  busy($("#uniSaveBtn"), true);
  try {
    const r = await api("/api/unified/save", "POST", {});
    toast(`Reporte guardado: ${r.pdf}`, "ok");
    loadReports();
  } catch (e) { toast(e.message, "err"); }
  busy($("#uniSaveBtn"), false);
});

async function loadKeys() {
  try {
    const k = await api("/api/network/keys");
    const card = (id, name, info, data) => `
      <div class="card" style="margin:0">
        <div class="card-head"><h2>${esc(name)}</h2>
          <span class="pill ${data.configured ? 'green' : 'amber'}">${data.configured ? 'Configurada' : 'No configurada'}</span></div>
        <p class="desc">${info}</p>
        ${data.configured ? `<div class="hint">Clave actual: <b class="mono">${esc(data.masked)}</b></div>` : ""}
        <label class="field"><span>Nueva clave</span><input type="text" id="key_${id}" placeholder="Pega aquí tu API key"></label>
        <div class="tag-row">
          <button class="btn sm" data-key-save="${id}">Guardar</button>
          ${data.configured ? `<button class="btn danger sm" data-key-del="${id}">Eliminar</button>` : ""}
        </div>
      </div>`;
    $("#keysBox").innerHTML =
      card("virustotal", "VirusTotal", "Reputación de IPs en DNS y conexiones sospechosas.", k.virustotal) +
      card("nvd", "NVD (CVEs)", "Aumenta el límite de consultas de vulnerabilidades.", k.nvd);
  } catch (e) { toast(e.message, "err"); }
}

document.addEventListener("click", async (e) => {
  const save = e.target.closest("[data-key-save]");
  const del = e.target.closest("[data-key-del]");
  if (save) {
    const id = save.dataset.keySave;
    try { await api("/api/network/keys", "POST", { provider: id, key: $(`#key_${id}`).value });
      toast("Clave guardada.", "ok"); loadKeys();
    } catch (err) { toast(err.message, "err"); }
  }
  if (del) {
    const id = del.dataset.keyDel;
    try { await api("/api/network/keys", "DELETE", { provider: id });
      toast("Clave eliminada.", "ok"); loadKeys();
    } catch (err) { toast(err.message, "err"); }
  }
});

async function loadReports() {
  try {
    const items = await api("/api/reports");
    if (!items.length) { $("#repList").innerHTML = `<p class="empty">Aún no hay reportes generados.</p>`; return; }
    $("#repList").innerHTML = table(["Archivo", "Tamaño", ""], items, (r) =>
      `<td class="mono">${esc(r.name)}</td><td>${(r.size / 1024).toFixed(1)} KB</td>
       <td><a class="btn ghost sm" href="/reports/${encodeURIComponent(r.name)}">Descargar</a></td>`);
  } catch (e) { toast(e.message, "err"); }
}
$("#repRefreshBtn").addEventListener("click", loadReports);

initWebScanners();
loadUnified();
