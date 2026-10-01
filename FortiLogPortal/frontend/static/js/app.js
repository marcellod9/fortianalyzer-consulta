/* FortiLogPortal - utilitários comuns da interface */
"use strict";

const FLP = (() => {
  const store = {
    get(k, d) { try { return localStorage.getItem(k) ?? d; } catch { return d; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch { /* sem armazenamento */ } },
  };

  // ---- tema claro/escuro -------------------------------------------------
  function applyTheme(t) {
    document.documentElement.setAttribute("data-bs-theme", t);
    const icon = document.getElementById("themeIcon");
    if (icon) icon.className = t === "dark" ? "bi bi-sun" : "bi bi-moon-stars";
  }
  const preferredTheme = () => store.get("flp-theme", matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  function initTheme() {
    applyTheme(preferredTheme());
    document.getElementById("themeToggle")?.addEventListener("click", () => {
      const next = document.documentElement.getAttribute("data-bs-theme") === "dark" ? "light" : "dark";
      store.set("flp-theme", next);
      applyTheme(next);
      document.dispatchEvent(new CustomEvent("flp-theme", { detail: next }));
    });
  }

  // ---- usuário da consulta (sem autenticação nesta fase) ------------------------
  function initUser() {
    const inp = document.getElementById("portalUser");
    if (!inp) return;
    inp.value = store.get("flp-user", "");
    inp.addEventListener("change", () => store.set("flp-user", inp.value.trim()));
  }
  const user = () => store.get("flp-user", "");

  // ---- chamadas à API -----------------------------------------------------------
  async function api(path, opts = {}) {
    const headers = { "Accept": "application/json", ...(opts.headers || {}) };
    if (user()) headers["X-Portal-User"] = user();
    if (opts.body && typeof opts.body !== "string") {
      headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(opts.body);
    }
    const resp = await fetch(path, { ...opts, headers });
    let data = null;
    try { data = await resp.json(); } catch { /* sem corpo */ }
    if (!resp.ok) {
      const msg = data && data.detail ? (typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail)) : `HTTP ${resp.status}`;
      throw new Error(msg);
    }
    return data;
  }

  function download(path) {
    // download com o header de usuário via fetch + blob
    const headers = user() ? { "X-Portal-User": user() } : {};
    return fetch(path, { headers }).then(async (r) => {
      if (!r.ok) { let d = {}; try { d = await r.json(); } catch {} throw new Error(d.detail || `HTTP ${r.status}`); }
      const cd = r.headers.get("Content-Disposition") || "";
      const name = (cd.match(/filename="([^"]+)"/) || [])[1] || "export";
      const blob = await r.blob();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = name;
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    }).catch((e) => toast(e.message, "danger"));
  }

  // ---- feedback -----------------------------------------------------------------
  function toast(msg, kind = "info") {
    const box = document.getElementById("toasts");
    const el = document.createElement("div");
    el.className = `toast align-items-center text-bg-${kind} border-0`;
    el.setAttribute("role", "alert");
    el.innerHTML = `<div class="d-flex"><div class="toast-body"></div><button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button></div>`;
    el.querySelector(".toast-body").textContent = msg;
    box.appendChild(el);
    const t = new bootstrap.Toast(el, { delay: kind === "danger" ? 9000 : 4000 });
    t.show();
    el.addEventListener("hidden.bs.toast", () => el.remove());
  }

  function busy(btn, on) {
    if (!btn) return;
    btn.disabled = on;
    btn.classList.toggle("loading", on);
  }

  // ---- formatação ---------------------------------------------------------------------
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  function actionBadge(row) {
    const a = row.acao || "";
    const cls = row.bloqueado ? "danger" : (a === "Allow" ? "success" : "secondary");
    return `<span class="badge text-bg-${cls}" title="${esc(row.acao_original)}">${esc(a)}</span>`;
  }

  function verdictClass(rep) {
    return { "Malicioso": "danger", "Suspeito": "warning", "Baixo risco": "info", "Confiável (exceção)": "success" }[rep] || "secondary";
  }
  function riskColor(score) {
    if (score >= 80) return "var(--bs-danger)";
    if (score >= 50) return "var(--bs-warning)";
    if (score > 0) return "var(--bs-info)";
    return "var(--bs-success)";
  }

  function toLocalInput(d) {
    const p = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
  }
  function setDefaultPeriod(startEl, endEl, hours = 24) {
    const end = new Date();
    const start = new Date(end.getTime() - hours * 3600 * 1000);
    if (startEl && !startEl.value) startEl.value = toLocalInput(start);
    if (endEl && !endEl.value) endEl.value = toLocalInput(end);
  }

  // ---- explicação simplificada --------------------------------------------------------
  function explainHtml(row) {
    const e = row.explicacao || {};
    const items = Object.entries(e).map(([k, v]) => `<dt class="col-4">${esc(k)}:</dt><dd class="col-8">${esc(v)}</dd>`).join("");
    return `<div class="card explain-card ${row.bloqueado ? "blocked" : ""} mb-2"><div class="card-body py-2"><dl class="row mb-0">${items}</dl></div></div>`;
  }

  // ---- tabela de logs -------------------------------------------------------------------
  const LOG_COLS = [
    ["data_hora", "Data/hora"], ["firewall", "Firewall"], ["usuario", "Usuário"], ["ip_origem", "IP origem"],
    ["porta_origem", "P. origem"], ["ip_destino", "IP destino"], ["porta_destino", "P. destino"], ["site", "Site"],
    ["url", "URL"], ["aplicacao", "Aplicação"], ["categoria", "Categoria"], ["regra", "Regra"], ["politica", "Política"],
    ["interface_entrada", "Int. entrada"], ["interface_saida", "Int. saída"], ["acao", "Ação"], ["motivo", "Motivo"],
  ];

  function renderLogTable(container, rows) {
    if (!rows.length) {
      container.innerHTML = `<div class="alert alert-secondary">Nenhum evento encontrado para os filtros informados.</div>`;
      return;
    }
    const head = LOG_COLS.map(([, l]) => `<th>${l}</th>`).join("");
    const body = rows.map((r, i) => `<tr data-i="${i}">${LOG_COLS.map(([k]) =>
      k === "acao" ? `<td>${actionBadge(r)}</td>` : `<td class="cell-trunc" title="${esc(r[k])}">${esc(r[k])}</td>`).join("")}</tr>`).join("");
    container.innerHTML = `<div class="table-responsive"><table class="table table-sm table-hover table-striped table-logs">
      <thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
    container.querySelectorAll("tbody tr").forEach((tr) => tr.addEventListener("click", () => showLogModal(rows[+tr.dataset.i])));
  }

  function showLogModal(row) {
    const m = document.getElementById("logModal");
    m.querySelector(".modal-body").innerHTML = explainHtml(row) +
      `<h6 class="mt-3">Todos os campos</h6><pre class="raw">${esc(JSON.stringify(row, null, 2))}</pre>`;
    bootstrap.Modal.getOrCreateInstance(m).show();
  }

  function exportButtons(container, resultId) {
    if (!container) return;
    container.innerHTML = resultId ? ["csv", "xlsx", "pdf"].map((f) =>
      `<button class="btn btn-sm btn-outline-secondary" data-fmt="${f}"><i class="bi bi-download"></i> ${f.toUpperCase()}</button>`).join(" ") : "";
    container.querySelectorAll("button").forEach((b) => b.addEventListener("click", () => download(`/api/export/${resultId}.${b.dataset.fmt}`)));
  }

  function formData(form) {
    const out = {};
    new FormData(form).forEach((v, k) => {
      if (v === "" || v === null) return;
      if (k === "devices") { (out.devices = out.devices || []).push(v); return; }
      out[k] = v;
    });
    form.querySelectorAll("input[type=checkbox]").forEach((c) => { out[c.name] = c.checked; });
    ["srcport", "dstport", "limit"].forEach((k) => { if (out[k] !== undefined) out[k] = parseInt(out[k], 10); });
    return out;
  }

  async function loadAdomsAndDevices(adomSel, devSel, defaultAdom) {
    try {
      const adoms = await api("/api/faz/adoms");
      adomSel.innerHTML = adoms.map((a) => `<option value="${esc(a.name)}" ${a.name === defaultAdom ? "selected" : ""}>${esc(a.name)}</option>`).join("");
    } catch (e) {
      adomSel.innerHTML = `<option value="${esc(defaultAdom)}">${esc(defaultAdom)}</option>`;
      toast("FortiAnalyzer: " + e.message, "warning");
    }
    const loadDevs = async () => {
      if (!devSel) return;
      try {
        const devs = await api(`/api/faz/adoms/${encodeURIComponent(adomSel.value)}/devices`);
        devSel.innerHTML = `<option value="">Todos os firewalls</option>` +
          devs.map((d) => `<option value="${esc(d.sn || d.name)}">${esc(d.name)}${d.ip ? " (" + esc(d.ip) + ")" : ""}</option>`).join("");
      } catch (e) { devSel.innerHTML = `<option value="">Todos os firewalls</option>`; }
    };
    adomSel.addEventListener("change", loadDevs);
    await loadDevs();
  }

  function initQuickPeriods() {
    document.querySelectorAll("[data-hours]").forEach((b) => b.addEventListener("click", () => {
      const s = document.getElementById("start"), e = document.getElementById("end");
      if (s) s.value = ""; if (e) e.value = "";
      setDefaultPeriod(s, e, +b.dataset.hours);
    }));
  }

  document.addEventListener("DOMContentLoaded", () => { initTheme(); initUser(); initQuickPeriods(); });
  applyTheme(preferredTheme());  // aplica já, antes do carregamento completo, para evitar "piscar"

  return { api, download, toast, busy, esc, actionBadge, verdictClass, riskColor, setDefaultPeriod, explainHtml,
           renderLogTable, exportButtons, formData, loadAdomsAndDevices, store };
})();
