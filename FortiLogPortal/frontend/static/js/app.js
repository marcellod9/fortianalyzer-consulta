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

  // ---- tabela de logs (visão simplificada para o N1) ----------------------------------
  const SITUATION = {
    bloqueado: { label: "Bloqueado", cls: "danger", icon: "bi-x-octagon-fill" },
    falha: { label: "Falhou", cls: "warning", icon: "bi-exclamation-triangle-fill" },
    permitido: { label: "Permitido", cls: "success", icon: "bi-check-circle-fill" },
  };
  const situationOf = (r) => r.situacao || (r.bloqueado ? "bloqueado" : "permitido");

  function situationBadge(r) {
    const s = SITUATION[situationOf(r)];
    return `<span class="badge text-bg-${s.cls} badge-situacao"><i class="bi ${s.icon}"></i> ${s.label}</span>`;
  }

  function shortTime(dt) {
    const m = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}:\d{2}:\d{2})/.exec(dt || "");
    return m ? `${m[3]}/${m[2]} ${m[4]}` : (dt || "");
  }

  const destinationOf = (r) => r.destino || r.site || r.ip_destino || "";
  const listDestination = (r) => r.site || r.ip_destino || destinationOf(r);  // a porta aparece na linha de baixo
  const whoOf = (r) => r.usuario || r.ip_origem || "";

  function groupRows(rows) {
    const map = new Map();
    rows.forEach((r) => {
      const k = [situationOf(r), whoOf(r), destinationOf(r), r.regra, r.motivo].join("|");
      const g = map.get(k);
      if (g) { g.vezes += 1; g.primeiro = r.data_hora; } else map.set(k, { ...r, vezes: 1, ultimo: r.data_hora, primeiro: r.data_hora });
    });
    return [...map.values()];
  }

  function rowHtml(r, i, grouped) {
    const sub = [r.aplicacao, r.servico].filter(Boolean).join(" · ");
    const who = r.usuario
      ? `<div class="fw-semibold">${esc(r.usuario)}</div><div class="small text-body-secondary">${esc(r.ip_origem)}</div>`
      : `<div class="fw-semibold">${esc(r.ip_origem)}</div><div class="small text-body-secondary">sem login</div>`;
    return `<tr data-i="${i}" class="sit-${situationOf(r)}">
      <td>${situationBadge(r)}</td>
      <td class="text-nowrap" title="${esc(r.data_hora)}">${esc(shortTime(r.data_hora))}</td>
      ${grouped ? `<td class="text-center">${r.vezes > 1 ? `<span class="badge rounded-pill text-bg-secondary">${r.vezes}x</span>` : ""}</td>` : ""}
      <td>${who}</td>
      <td class="cell-dest"><div class="fw-semibold cell-trunc" title="${esc(destinationOf(r))}">${esc(listDestination(r))}</div>
        <div class="small text-body-secondary cell-trunc" title="${esc(sub)}">${esc(sub)}</div></td>
      <td class="cell-motivo">${esc(r.motivo)}</td></tr>`;
  }

  function renderLogTable(container, rows) {
    if (!rows.length) {
      container.innerHTML = `<div class="alert alert-secondary">Nenhum evento encontrado para os filtros informados.</div>`;
      return;
    }
    const count = (s) => rows.filter((r) => situationOf(r) === s).length;
    const n = { bloqueado: count("bloqueado"), falha: count("falha"), permitido: count("permitido") };
    const state = { filtro: n.bloqueado ? "bloqueado" : "todos", texto: "", agrupar: store.get("flp-agrupar", "1") === "1" };
    const chip = (k, label, cls) => `<input type="radio" class="btn-check" name="sit-${container.id}" id="sit-${container.id}-${k}" value="${k}" ${state.filtro === k ? "checked" : ""}>
      <label class="btn btn-sm btn-outline-${cls}" for="sit-${container.id}-${k}">${label}</label>`;
    container.innerHTML = `
      <div class="d-flex flex-wrap gap-2 align-items-center mb-2 log-toolbar">
        <div class="btn-group" role="group" aria-label="Situação">
          ${chip("todos", `Todos (${rows.length})`, "secondary")}
          ${chip("bloqueado", `<i class="bi bi-x-octagon"></i> Bloqueados (${n.bloqueado})`, "danger")}
          ${n.falha ? chip("falha", `<i class="bi bi-exclamation-triangle"></i> Falhas (${n.falha})`, "warning") : ""}
          ${chip("permitido", `<i class="bi bi-check-circle"></i> Permitidos (${n.permitido})`, "success")}
        </div>
        <input type="search" class="form-control form-control-sm log-search" placeholder="Filtrar nesta lista (usuário, site, IP...)">
        <div class="form-check form-switch mb-0"><input class="form-check-input" type="checkbox" id="agr-${container.id}" ${state.agrupar ? "checked" : ""}>
          <label class="form-check-label small" for="agr-${container.id}" title="Junta eventos iguais (mesmo usuário, destino e resultado) em uma linha">Agrupar repetidos</label></div>
        <span class="small text-body-secondary ms-auto"><i class="bi bi-mouse"></i> Dê dois cliques em um evento para ver os detalhes e o que fazer</span>
      </div>
      <div class="table-responsive"><table class="table table-sm table-hover table-logs align-middle mb-0"><thead></thead><tbody></tbody></table></div>
      <div class="small text-body-secondary mt-1 log-count"></div>`;
    const thead = container.querySelector("thead"), tbody = container.querySelector("tbody");
    let shown = [];
    const draw = () => {
      const t = state.texto.toLowerCase();
      let list = rows.filter((r) => state.filtro === "todos" || situationOf(r) === state.filtro);
      if (t) list = list.filter((r) => [r.usuario, r.ip_origem, r.ip_destino, r.site, r.url, r.aplicacao, r.regra, r.motivo, r.categoria]
        .some((v) => String(v || "").toLowerCase().includes(t)));
      shown = state.agrupar ? groupRows(list) : list;
      thead.innerHTML = `<tr><th>Situação</th><th>Quando</th>${state.agrupar ? '<th class="text-center">Vezes</th>' : ""}<th>Quem</th><th>Destino</th><th>O que aconteceu</th></tr>`;
      tbody.innerHTML = shown.length ? shown.map((r, i) => rowHtml(r, i, state.agrupar)).join("")
        : `<tr><td colspan="6" class="text-center text-body-secondary py-3">Nenhum evento com este filtro.</td></tr>`;
      container.querySelector(".log-count").textContent = state.agrupar
        ? `${shown.length} linha(s) agrupando ${list.length} evento(s)` : `${shown.length} evento(s)`;
    };
    container.querySelectorAll(`input[name="sit-${container.id}"]`).forEach((r) => r.addEventListener("change", () => { state.filtro = r.value; draw(); }));
    container.querySelector(".log-search").addEventListener("input", (e) => { state.texto = e.target.value.trim(); draw(); });
    container.querySelector(`#agr-${container.id}`).addEventListener("change", (e) => {
      state.agrupar = e.target.checked; store.set("flp-agrupar", state.agrupar ? "1" : "0"); draw();
    });
    let selected = null;
    tbody.addEventListener("click", (e) => {
      const tr = e.target.closest("tr[data-i]"); if (!tr) return;
      selected?.classList.remove("table-active"); selected = tr; tr.classList.add("table-active");
    });
    tbody.addEventListener("dblclick", (e) => {
      const tr = e.target.closest("tr[data-i]"); if (tr) showLogModal(shown[+tr.dataset.i]);
    });
    draw();
  }

  function fieldList(pairs) {
    return `<dl class="row mb-0 detail-list">${pairs.filter(([, v]) => v !== undefined && v !== null && v !== "")
      .map(([k, v]) => `<dt class="col-12">${esc(k)}</dt><dd class="col-12">${esc(v)}</dd>`).join("") || '<dd class="col-12 text-body-secondary">-</dd>'}</dl>`;
  }

  function ticketText(r) {
    const s = SITUATION[situationOf(r)].label;
    return [
      `Data/hora: ${r.data_hora}${r.vezes > 1 ? ` (${r.vezes} ocorrências desde ${r.primeiro})` : ""}`,
      `Usuário: ${r.usuario || "(sem login)"} - IP ${r.ip_origem || "-"}`,
      `Destino: ${destinationOf(r)}${r.url && r.url !== r.site ? ` (${r.url})` : ""}`,
      `Porta/serviço: ${r.servico || r.porta_destino || "-"}${r.aplicacao ? ` - Aplicação: ${r.aplicacao}` : ""}`,
      `Resultado: ${s}`,
      `Motivo: ${r.motivo || "-"}`,
      `Regra: ${r.regra || "-"}${r.politica ? ` - Perfil: ${r.politica}` : ""}`,
      `Firewall: ${r.firewall || "-"}`,
    ].join("\n");
  }

  async function copyText(text) {
    try { await navigator.clipboard.writeText(text); }
    catch {
      const ta = document.createElement("textarea"); ta.value = text; document.body.appendChild(ta);
      ta.select(); document.execCommand("copy"); ta.remove();
    }
    toast("Resumo copiado. Cole no chamado.", "success");
  }

  function showLogModal(r) {
    const m = document.getElementById("logModal");
    const sit = SITUATION[situationOf(r)];
    const repTarget = r.site || r.ip_destino;
    m.querySelector(".modal-title").textContent = "Detalhes do evento";
    m.querySelector(".modal-body").innerHTML = `
      <div class="alert alert-${sit.cls} d-flex gap-3 align-items-start mb-3">
        <i class="bi ${sit.icon} fs-3"></i>
        <div><div class="fs-5 fw-bold">${esc(r.explicacao?.Resultado || sit.label)}</div><div>${esc(r.motivo)}</div>
          <div class="small mt-1">${esc(r.data_hora)}${r.vezes > 1 ? ` · ${r.vezes} vezes desde ${esc(r.primeiro)}` : ""}</div></div>
      </div>
      ${r.orientacao ? `<div class="card border-primary mb-3"><div class="card-body py-2">
        <div class="fw-semibold text-primary"><i class="bi bi-lightbulb"></i> O que fazer</div><div>${esc(r.orientacao)}</div></div></div>` : ""}
      <div class="row g-2">
        <div class="col-md-4"><div class="card h-100"><div class="card-header py-1 small fw-semibold"><i class="bi bi-person"></i> Quem</div><div class="card-body py-2">
          ${fieldList([["Usuário", r.usuario || "(sem login)"], ["IP de origem", r.ip_origem], ["Porta de origem", r.porta_origem], ["Entrou pela interface", r.interface_entrada]])}</div></div></div>
        <div class="col-md-4"><div class="card h-100"><div class="card-header py-1 small fw-semibold"><i class="bi bi-globe"></i> Destino</div><div class="card-body py-2">
          ${fieldList([["Site", r.site], ["URL", r.url], ["IP de destino", r.ip_destino], ["Porta / serviço", r.servico || r.porta_destino],
                       ["Aplicação", r.aplicacao], ["Categoria", r.categoria], ["Saiu pela interface", r.interface_saida]])}</div></div></div>
        <div class="col-md-4"><div class="card h-100"><div class="card-header py-1 small fw-semibold"><i class="bi bi-bricks"></i> Firewall</div><div class="card-body py-2">
          ${fieldList([["Firewall", r.firewall], ["Regra", r.regra], ["Perfil de segurança", r.politica], ["Ação registrada", r.acao_original], ["Tipo de log", r.tipo_log]])}</div></div></div>
      </div>
      <div class="d-flex flex-wrap gap-2 mt-3">
        <button class="btn btn-sm btn-primary" data-act="copy"><i class="bi bi-clipboard"></i> Copiar resumo para o chamado</button>
        ${repTarget ? `<a class="btn btn-sm btn-outline-secondary" target="_blank" href="/reputacao?q=${encodeURIComponent(repTarget)}"><i class="bi bi-shield-check"></i> Consultar reputação de ${esc(repTarget)}</a>` : ""}
        <button class="btn btn-sm btn-outline-secondary ms-auto" data-bs-toggle="collapse" data-bs-target="#rawLog"><i class="bi bi-code"></i> Log original (para N2)</button>
      </div>
      <div class="collapse mt-2" id="rawLog"><pre class="raw">${esc(JSON.stringify(r.log_original || r, null, 2))}</pre></div>`;
    m.querySelector('[data-act="copy"]').addEventListener("click", () => copyText(ticketText(r)));
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
