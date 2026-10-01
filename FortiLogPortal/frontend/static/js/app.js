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
    return { "Malicioso": "danger", "Suspeito": "warning", "Baixo risco": "info", "Confiável (exceção)": "success", "Não foi possível consultar": "warning", "Inconclusivo": "warning", "Sem risco detectado (Sandbox)": "success", "Sem risco conhecido": "success" }[rep] || "secondary";
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
  // alguns logs trazem a URL codificada (https%3A%2F%2Fsite%2F); na tela ela aparece legível
  const readableUrl = (u) => {
    if (!u || !/%[0-9a-f]{2}/i.test(u)) return u || "";
    try { return decodeURIComponent(u); } catch { return u; }
  };
  const listDestination = (r) => r.site || r.ip_destino || destinationOf(r);  // a porta aparece na linha de baixo
  const whoOf = (r) => r.usuario || r.ip_origem || "";
  const LOGTYPE_LABEL = { traffic: "Regras do firewall (tráfego)", webfilter: "Filtro web", "app-ctrl": "Controle de aplicações",
                          dns: "Filtro DNS", ips: "IPS", virus: "Antivírus", ssl: "Inspeção SSL", event: "Eventos do sistema" };
  const logtypeLabel = (t) => LOGTYPE_LABEL[t] || t || "";
  // máquina de origem (identificação de dispositivos do FortiGate): nome, MAC e sistema
  const machineOf = (r) => r.maquina || "";

  function groupRows(rows) {
    const map = new Map();
    rows.forEach((r) => {
      const k = [situationOf(r), whoOf(r), destinationOf(r), r.regra, r.motivo].join("|");
      const g = map.get(k);
      if (g) { g.vezes += 1; g.primeiro = r.data_hora; } else map.set(k, { ...r, vezes: 1, ultimo: r.data_hora, primeiro: r.data_hora });
    });
    return [...map.values()];
  }

  // ---- colunas da lista (o usuário escolhe quais e em que ordem, como no FortiAnalyzer) ----
  const txt = (k, cls = "") => (r) => `<td class="${cls}" title="${esc(r[k])}">${esc(r[k])}</td>`;
  const LOG_COLUMNS = [
    { key: "quando", label: "Data/Hora", on: true, td: (r) => `<td class="text-nowrap" title="${esc(r.data_hora)}">${esc(shortTime(r.data_hora))}</td>` },
    { key: "vezes", label: "Vezes", on: true, grouped: true,
      td: (r) => `<td class="text-center">${r.vezes > 1 ? `<span class="badge rounded-pill text-bg-secondary">${r.vezes}x</span>` : ""}</td>` },
    { key: "quem", label: "Origem (usuário, IP e máquina)", head: "Origem", on: true, td: (r) => {
        const sub = r.usuario ? [r.ip_origem, machineOf(r)] : [machineOf(r), "sem login"];
        const subText = sub.filter(Boolean).join(" · ");
        return `<td class="cell-dest"><div class="fw-semibold cell-trunc">${esc(r.usuario || r.ip_origem)}</div>
          <div class="small text-body-secondary cell-trunc" title="${esc(subText)}">${esc(subText)}</div></td>`; } },
    { key: "destino", label: "Destino (site/IP e serviço)", head: "Destino", on: true, td: (r) => {
        const sub = [r.aplicacao, r.servico].filter(Boolean).join(" · ");
        return `<td class="cell-dest"><div class="fw-semibold cell-trunc" title="${esc(destinationOf(r))}">${esc(listDestination(r))}</div>
          <div class="small text-body-secondary cell-trunc" title="${esc(sub)}">${esc(sub)}</div></td>`; } },
    { key: "site", label: "Site", on: true, td: txt("site", "cell-trunc") },
    { key: "situacao", label: "Situação", on: true, td: (r) => `<td>${situationBadge(r)}</td>` },
    { key: "regra", label: "Regra (nº e nome)", head: "Regra", on: true, td: (r) => {
        const [id, nome] = r.regra_id !== undefined ? [r.regra_id, r.regra_nome] : String(r.regra || "").split(" - ");
        return `<td class="cell-dest" title="${esc(r.regra)}"><div class="fw-semibold">${esc(id || r.regra || "")}</div>
          <div class="small text-body-secondary cell-trunc">${esc(nome || "")}</div></td>`; } },
    { key: "motivo", label: "O que aconteceu", on: true, td: (r) => `<td class="cell-motivo">${esc(r.motivo)}</td>` },
    { key: "firewall", label: "Firewall", td: txt("firewall", "text-nowrap") },
    { key: "usuario", label: "Usuário", td: txt("usuario", "cell-trunc") },
    { key: "ip_origem", label: "IP de origem", td: txt("ip_origem", "text-nowrap") },
    { key: "porta_origem", label: "Porta de origem", td: txt("porta_origem") },
    { key: "ip_destino", label: "IP de destino", td: txt("ip_destino", "text-nowrap") },
    { key: "servico", label: "Porta / serviço", td: txt("servico", "text-nowrap") },
    { key: "url", label: "URL", td: (r) => `<td class="cell-trunc" title="${esc(readableUrl(r.url))}">${esc(readableUrl(r.url))}</td>` },
    { key: "aplicacao", label: "Aplicação", td: txt("aplicacao", "cell-trunc") },
    { key: "categoria", label: "Categoria", td: txt("categoria", "cell-trunc") },
    { key: "politica", label: "Perfil de segurança", td: txt("politica", "cell-trunc") },
    { key: "interface_entrada", label: "Interface de entrada", td: txt("interface_entrada", "text-nowrap") },
    { key: "interface_saida", label: "Interface de saída", td: txt("interface_saida", "text-nowrap") },
    { key: "acao_original", label: "Ação registrada", td: txt("acao_original", "text-nowrap") },
    { key: "tipo_log", label: "Tipo de log", td: (r) => `<td class="text-nowrap">${esc(logtypeLabel(r.tipo_log))}</td>` },
    { key: "maquina", label: "Máquina (nome)", td: txt("maquina", "cell-trunc") },
    { key: "mac", label: "MAC de origem", td: txt("mac", "text-nowrap") },
    { key: "sistema", label: "Sistema da máquina", td: txt("sistema", "cell-trunc") },
  ];
  const COL_BY_KEY = Object.fromEntries(LOG_COLUMNS.map((c) => [c.key, c]));
  const COLS_STORE = "flp-colunas";
  const defaultCols = () => LOG_COLUMNS.map((c) => ({ key: c.key, on: !!c.on }));
  function loadCols() {
    let saved = [];
    try { saved = JSON.parse(store.get(COLS_STORE, "[]")).filter((c) => COL_BY_KEY[c.key]); } catch { /* padrão */ }
    if (!saved.length) return defaultCols();
    const known = new Set(saved.map((c) => c.key));
    return [...saved, ...defaultCols().filter((c) => !known.has(c.key)).map((c) => ({ ...c, on: false }))];  // colunas novas entram ocultas
  }
  const saveCols = (cols) => store.set(COLS_STORE, JSON.stringify(cols));
  const WIDTHS_STORE = "flp-larguras";
  const loadWidths = () => { try { return JSON.parse(store.get(WIDTHS_STORE, "{}")) || {}; } catch { return {}; } };
  const saveWidths = (w) => store.set(WIDTHS_STORE, JSON.stringify(w));

  // Largura das colunas: arraste a borda direita do título. Duplo clique na borda volta ao automático.
  function enableColumnResize(table, onDone) {
    table.querySelector("thead").addEventListener("mousedown", (e) => {
      const grip = e.target.closest(".col-resizer"); if (!grip) return;
      e.preventDefault();
      const ths = [...table.querySelectorAll("thead th")];
      const widths = loadWidths();
      // fixa as larguras atuais das outras colunas (mínimo de 90px: uma coluna vazia agora pode ter dados na próxima busca)
      ths.forEach((th) => {
        if (!widths[th.dataset.key]) widths[th.dataset.key] = Math.max(th.dataset.key === "vezes" ? 56 : 90, Math.round(th.getBoundingClientRect().width));
      });
      const th = grip.closest("th"), key = th.dataset.key, x0 = e.clientX, w0 = widths[key];
      applyWidths(table, widths);
      document.body.classList.add("col-resizing");
      const move = (ev) => { widths[key] = Math.max(48, Math.round(w0 + ev.clientX - x0)); applyWidths(table, widths); };
      const up = () => {
        removeEventListener("mousemove", move); removeEventListener("mouseup", up);
        document.body.classList.remove("col-resizing");
        saveWidths(widths); onDone && onDone();
      };
      addEventListener("mousemove", move); addEventListener("mouseup", up);
    });
    table.querySelector("thead").addEventListener("dblclick", (e) => {
      const grip = e.target.closest(".col-resizer"); if (!grip) return;
      const widths = loadWidths(); delete widths[grip.closest("th").dataset.key]; saveWidths(widths); onDone && onDone();
    });
  }
  function applyWidths(table, widths) {
    const ths = [...table.querySelectorAll("thead th")];
    const fixed = ths.some((th) => widths[th.dataset.key]);
    table.classList.toggle("table-fixed", fixed);
    let total = 0;
    ths.forEach((th) => {
      const w = widths[th.dataset.key];
      th.style.width = w ? `${w}px` : "";
      total += w || 140;  // coluna sem largura definida divide o espaço restante
    });
    table.style.width = fixed ? `${Math.max(total, table.parentElement.clientWidth)}px` : "";
  }

  // Botão "Colunas": buscar, marcar/desmarcar, arrastar para mudar a posição, voltar ao padrão
  function columnChooser(box, getCols, setCols) {
    box.innerHTML = `<div class="dropdown">
        <button type="button" class="btn btn-sm btn-outline-secondary" data-bs-toggle="dropdown" data-bs-auto-close="outside" title="Escolher e ordenar colunas"><i class="bi bi-gear"></i> Colunas</button>
        <div class="dropdown-menu dropdown-menu-end p-2 cc-menu">
          <input type="search" class="form-control form-control-sm mb-1 cc-search" placeholder="Buscar coluna">
          <div class="small text-body-secondary mb-1"><i class="bi bi-arrows-move"></i> Arraste para mudar a ordem</div>
          <div class="cc-list"></div>
          <div class="border-top mt-1 pt-1">
            <div class="form-check"><input class="form-check-input cc-all" type="checkbox" id="${box.id}-ccall"><label class="form-check-label small" for="${box.id}-ccall">Marcar todas</label></div>
            <button type="button" class="btn btn-link btn-sm p-0 cc-reset"><i class="bi bi-arrow-counterclockwise"></i> Voltar ao padrão (ordem e larguras)</button>
          </div></div></div>`;
    const list = box.querySelector(".cc-list"), search = box.querySelector(".cc-search"), all = box.querySelector(".cc-all");
    let dragKey = null;
    const draw = () => {
      const cols = getCols(), t = search.value.trim().toLowerCase();
      list.innerHTML = cols.filter((c) => !t || COL_BY_KEY[c.key].label.toLowerCase().includes(t)).map((c) => `
        <div class="cc-item d-flex align-items-center gap-2" draggable="${t ? "false" : "true"}" data-key="${c.key}">
          <i class="bi bi-grip-vertical text-body-secondary cc-grip"></i>
          <input class="form-check-input mt-0" type="checkbox" id="${box.id}-cc-${c.key}" ${c.on ? "checked" : ""}>
          <label class="form-check-label small flex-grow-1" for="${box.id}-cc-${c.key}">${esc(COL_BY_KEY[c.key].label)}</label></div>`).join("");
      all.checked = cols.every((c) => c.on);
    };
    list.addEventListener("change", (e) => {
      const key = e.target.closest(".cc-item")?.dataset.key; if (!key) return;
      const cols = getCols().map((c) => c.key === key ? { ...c, on: e.target.checked } : c);
      if (!cols.some((c) => c.on)) { e.target.checked = true; return; }  // pelo menos uma coluna
      setCols(cols); draw();
    });
    all.addEventListener("change", () => { setCols(getCols().map((c) => ({ ...c, on: all.checked || c.key === "situacao" }))); draw(); });
    box.querySelector(".cc-reset").addEventListener("click", () => { saveWidths({}); setCols(defaultCols()); draw(); });
    search.addEventListener("input", draw);
    search.addEventListener("keydown", (e) => { if (e.key === "Enter") e.preventDefault(); });
    list.addEventListener("dragstart", (e) => {
      const it = e.target.closest(".cc-item"); if (!it) return;
      dragKey = it.dataset.key; it.classList.add("cc-dragging"); e.dataTransfer.effectAllowed = "move";
      e.dataTransfer.setData("text/plain", dragKey);
    });
    list.addEventListener("dragover", (e) => {
      const it = e.target.closest(".cc-item"); if (!it || !dragKey || it.dataset.key === dragKey) return;
      e.preventDefault();
      const after = e.clientY > it.getBoundingClientRect().top + it.offsetHeight / 2;
      list.querySelectorAll(".cc-over-top,.cc-over-bottom").forEach((x) => x.classList.remove("cc-over-top", "cc-over-bottom"));
      it.classList.add(after ? "cc-over-bottom" : "cc-over-top");
    });
    list.addEventListener("drop", (e) => {
      const it = e.target.closest(".cc-item"); if (!it || !dragKey) return;
      e.preventDefault();
      const after = it.classList.contains("cc-over-bottom");
      const cols = getCols(), moving = cols.find((c) => c.key === dragKey);
      const rest = cols.filter((c) => c.key !== dragKey);
      const idx = rest.findIndex((c) => c.key === it.dataset.key) + (after ? 1 : 0);
      rest.splice(idx, 0, moving);
      setCols(rest); draw();
    });
    list.addEventListener("dragend", () => { dragKey = null; draw(); });
    box.querySelector("[data-bs-toggle]").addEventListener("shown.bs.dropdown", () => { search.value = ""; draw(); search.focus(); });
    draw();
  }

  // Valores de cada coluna que podem virar filtro (botão direito)
  function cellFilters(r, col) {
    const lg = r.log_original || {};
    const out = [];
    const push = (field, value, text) => { if (value !== undefined && value !== null && value !== "") out.push({ field, value: String(value), text: text ?? value }); };
    if (col === "quem") { push("user", r.usuario); push("srcip", r.ip_origem); push("srcname", r.maquina); push("srcmac", r.mac); }
    if (col === "destino") {
      push("hostname", r.site); push("dstip", r.ip_destino); push("dstport", r.porta_destino, r.servico || r.porta_destino);
      push("app", r.aplicacao);
    }
    if (col === "situacao") push("action", lg.action || r.acao_original);
    if (col === "motivo") { push("policy", lg.policyid ?? "", r.regra); push("category", r.categoria); }
    const simple = { usuario: "user", ip_origem: "srcip", porta_origem: "srcport", ip_destino: "dstip", site: "hostname",
                     url: "url", aplicacao: "app", categoria: "category", politica: "profile", interface_entrada: "srcintf",
                     interface_saida: "dstintf", acao_original: "action",
                     maquina: "srcname", mac: "srcmac" };
    if (simple[col]) push(simple[col], r[col]);
    if (col === "firewall") push("devname", r.firewall);
    if (col === "servico") push("dstport", r.porta_destino, r.servico);
    if (col === "regra") push("policy", lg.policyid ?? "", r.regra);
    return out;
  }

  let ctxMenu = null;
  function showContextMenu(ev, items, onFilter) {
    ctxMenu?.remove();
    if (!items.length) return;
    ev.preventDefault();
    ctxMenu = document.createElement("div");
    ctxMenu.className = "dropdown-menu show shadow flp-ctx";
    ctxMenu.innerHTML = items.map((it, i) => `
      <button type="button" class="dropdown-item small" data-i="${i}" data-op="="><i class="bi bi-zoom-in text-success"></i> Filtrar <b>${esc(FILTER_LABEL[it.field])}</b> = ${esc(it.text)}</button>
      <button type="button" class="dropdown-item small" data-i="${i}" data-op="!="><i class="bi bi-zoom-out text-danger"></i> Excluir <b>${esc(FILTER_LABEL[it.field])}</b> ≠ ${esc(it.text)}</button>`)
      .join('<div class="dropdown-divider my-1"></div>');
    document.body.appendChild(ctxMenu);
    const w = ctxMenu.offsetWidth, h = ctxMenu.offsetHeight;
    ctxMenu.style.left = `${Math.min(ev.clientX, innerWidth - w - 8)}px`;
    ctxMenu.style.top = `${Math.min(ev.clientY, innerHeight - h - 8)}px`;
    const menu = ctxMenu;
    menu.addEventListener("click", (e) => {
      const b = e.target.closest("[data-i]"); if (!b) return;
      const it = items[+b.dataset.i];
      menu.remove(); if (ctxMenu === menu) ctxMenu = null;
      onFilter(it.field, b.dataset.op, it.value);
    });
  }
  const closeCtx = (e) => { if (ctxMenu && !(e && e.target instanceof Node && ctxMenu.contains(e.target))) { ctxMenu.remove(); ctxMenu = null; } };
  ["click", "scroll", "resize"].forEach((t) => addEventListener(t, closeCtx, true));
  addEventListener("keydown", (e) => { if (e.key === "Escape") { ctxMenu?.remove(); ctxMenu = null; } });

  // Devolve um objeto com update(rows) para trocar as linhas sem perder busca, filtro e colunas (tempo real).
  function renderLogTable(container, rows, opts = {}) {
    if (!rows.length) {
      container.innerHTML = `<div class="alert alert-secondary">${esc(opts.empty || "Nenhum evento encontrado para os filtros informados.")}</div>`;
      return null;
    }
    const count = (s) => rows.filter((r) => situationOf(r) === s).length;
    let n = { bloqueado: count("bloqueado"), falha: count("falha"), permitido: count("permitido") };
    // mantém a escolha do usuário entre uma pesquisa e outra (ex.: filtro aplicado pelo botão direito)
    let filtro = container.dataset.sit || (n.bloqueado ? "bloqueado" : "todos");
    if (filtro !== "todos" && !n[filtro]) filtro = "todos";
    const state = { filtro, texto: "", agrupar: store.get("flp-agrupar", "1") === "1" };
    const chip = (k, label, cls) => `<input type="radio" class="btn-check" name="sit-${container.id}" id="sit-${container.id}-${k}" value="${k}" ${state.filtro === k ? "checked" : ""}>
      <label class="btn btn-sm btn-outline-${cls}" for="sit-${container.id}-${k}">${label} (<span data-n="${k}"></span>)</label>`;
    container.innerHTML = `
      <div class="d-flex flex-wrap gap-2 align-items-center mb-2 log-toolbar">
        <div class="btn-group" role="group" aria-label="Situação">
          ${chip("todos", "Todos", "secondary")}
          ${chip("bloqueado", `<i class="bi bi-x-octagon"></i> Bloqueados`, "danger")}
          ${chip("falha", `<i class="bi bi-exclamation-triangle"></i> Falhas`, "warning")}
          ${chip("permitido", `<i class="bi bi-check-circle"></i> Permitidos`, "success")}
        </div>
        <input type="search" class="form-control form-control-sm log-search" placeholder="Filtrar nesta lista (usuário, site, IP...)">
        <div class="form-check form-switch mb-0"><input class="form-check-input" type="checkbox" id="agr-${container.id}" ${state.agrupar ? "checked" : ""}>
          <label class="form-check-label small" for="agr-${container.id}" title="Junta eventos iguais (mesmo usuário, destino e resultado) em uma linha">Agrupar repetidos</label></div>
        <span class="cc-box" id="cc-${container.id}"></span>
        <span class="small text-body-secondary ms-auto"><i class="bi bi-mouse"></i> Dois cliques: detalhes e o que fazer${opts.onFilter ? " · Botão direito: filtrar ou excluir o valor" : ""}</span>
      </div>
      <div class="table-responsive"><table class="table table-sm table-hover table-logs align-middle mb-0"><thead></thead><tbody></tbody></table></div>
      <div class="small text-body-secondary mt-1 log-count"></div>`;
    const thead = container.querySelector("thead"), tbody = container.querySelector("tbody");
    let shown = [];
    const draw = () => {
      const t = state.texto.toLowerCase();
      let list = rows.filter((r) => state.filtro === "todos" || situationOf(r) === state.filtro);
      if (t) list = list.filter((r) => [r.usuario, r.ip_origem, r.maquina, r.mac, r.ip_destino, r.site, r.url, r.aplicacao, r.regra, r.motivo, r.categoria]
        .some((v) => String(v || "").toLowerCase().includes(t)));
      shown = state.agrupar ? groupRows(list) : list;
      const cols = loadCols().filter((c) => c.on && (!COL_BY_KEY[c.key].grouped || state.agrupar)).map((c) => COL_BY_KEY[c.key]);
      thead.innerHTML = `<tr>${cols.map((c) => `<th class="text-nowrap" data-key="${c.key}">${esc(c.head || c.label)}<span class="col-resizer" title="Arraste para ajustar a largura · duplo clique: automático"></span></th>`).join("")}</tr>`;
      applyWidths(thead.closest("table"), loadWidths());
      tbody.innerHTML = shown.length ? shown.map((r, i) => `<tr data-i="${i}" class="sit-${situationOf(r)}${r._novo ? " row-new" : ""}">${cols.map((c) =>
          c.td(r).replace(/^<td/, `<td data-col="${c.key}"`)).join("")}</tr>`).join("")
        : `<tr><td colspan="${cols.length}" class="text-center text-body-secondary py-3">Nenhum evento com este filtro.</td></tr>`;
      container.querySelector(".log-count").textContent = state.agrupar
        ? `${shown.length} linha(s) agrupando ${list.length} evento(s)` : `${shown.length} evento(s)`;
    };
    // contadores dos botões; o de "Falhas" só aparece quando há falhas de conexão na lista
    const syncChips = () => {
      container.querySelectorAll("[data-n]").forEach((el) => { el.textContent = el.dataset.n === "todos" ? rows.length : n[el.dataset.n]; });
      container.querySelector(`label[for="sit-${container.id}-falha"]`).classList.toggle("d-none", !n.falha);
      // lista só com bloqueios (diagnóstico): "Permitidos (0)" daria a impressão de que não houve acesso liberado
      container.querySelector(`label[for="sit-${container.id}-permitido"]`).classList.toggle("d-none", !!opts.blockedOnly && !n.permitido);
    };
    container.querySelectorAll(`input[name="sit-${container.id}"]`).forEach((r) => r.addEventListener("change", () => { state.filtro = container.dataset.sit = r.value; draw(); }));
    container.querySelector(".log-search").addEventListener("input", (e) => { state.texto = e.target.value.trim(); draw(); });
    container.querySelector(`#agr-${container.id}`).addEventListener("change", (e) => {
      state.agrupar = e.target.checked; store.set("flp-agrupar", state.agrupar ? "1" : "0"); draw();
    });
    columnChooser(container.querySelector(`#cc-${container.id}`), loadCols, (cols) => { saveCols(cols); draw(); });
    enableColumnResize(container.querySelector("table.table-logs"), draw);
    let selected = null;
    tbody.addEventListener("click", (e) => {
      const tr = e.target.closest("tr[data-i]"); if (!tr) return;
      selected?.classList.remove("table-active"); selected = tr; tr.classList.add("table-active");
    });
    if (opts.onFilter) tbody.addEventListener("contextmenu", (e) => {
      const td = e.target.closest("td[data-col]"), tr = e.target.closest("tr[data-i]");
      if (!td || !tr) return;
      selected?.classList.remove("table-active"); selected = tr; tr.classList.add("table-active");
      showContextMenu(e, cellFilters(shown[+tr.dataset.i], td.dataset.col), opts.onFilter);
    });
    tbody.addEventListener("dblclick", (e) => {
      const tr = e.target.closest("tr[data-i]"); if (tr) showLogModal(shown[+tr.dataset.i]);
    });
    syncChips();
    draw();
    return {
      update(newRows) {
        rows = newRows;
        n = { bloqueado: count("bloqueado"), falha: count("falha"), permitido: count("permitido") };
        syncChips();
        draw();
      },
    };
  }

  function fieldList(pairs) {
    return `<dl class="row mb-0 detail-list">${pairs.filter(([, v]) => v !== undefined && v !== null && v !== "")
      .map(([k, v]) => `<dt class="col-12">${esc(k)}</dt><dd class="col-12">${esc(v)}</dd>`).join("") || '<dd class="col-12 text-body-secondary">-</dd>'}</dl>`;
  }

  function ticketText(r) {
    const s = SITUATION[situationOf(r)].label;
    return [
      `Data/hora: ${r.data_hora}${r.vezes > 1 ? ` (${r.vezes} ocorrências desde ${r.primeiro})` : ""}`,
      `Usuário: ${r.usuario || "(sem login)"} - IP ${r.ip_origem || "-"}${r.maquina ? ` - máquina ${r.maquina}` : ""}${r.mac ? ` (MAC ${r.mac})` : ""}`,
      `Destino: ${destinationOf(r)}${r.url && r.url !== r.site ? ` (${readableUrl(r.url)})` : ""}`,
      `Porta/serviço: ${r.servico || r.porta_destino || "-"}${r.aplicacao ? ` - Aplicação: ${r.aplicacao}` : ""}`,
      `Resultado: ${s}`,
      `Motivo: ${r.motivo || "-"}`,
      `Regra: ${r.regra || "-"}${r.politica ? ` - Perfil: ${r.politica}` : ""}`,
      `Firewall: ${r.firewall || "-"}`,
      ...Object.values(r._rep || {}).map((rep) => `Reputação (Vision One) de ${rep.indicador}: ${rep.reputacao} (score ${rep.risk_score}/100)`),
      ...(r._maq ? [machineTicketLine(r._maq)] : []),
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
    const repTargets = [r.site, r.ip_destino].filter((v, i, a) => v && a.indexOf(v) === i);
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
        <div class="col-md-4"><div class="card h-100"><div class="card-header py-1 small fw-semibold"><i class="bi bi-person"></i> Origem</div><div class="card-body py-2">
          ${fieldList([["Usuário", r.usuario || "(sem login)"], ["IP de origem", r.ip_origem], ["Máquina", r.maquina], ["MAC", r.mac],
                       ["Sistema", [r.sistema, r.tipo_dispositivo, r.fabricante].filter(Boolean).join(" · ")],
                       ["Porta de origem", r.porta_origem], ["Entrou pela interface", r.interface_entrada]])}</div></div></div>
        <div class="col-md-4"><div class="card h-100"><div class="card-header py-1 small fw-semibold"><i class="bi bi-globe"></i> Destino</div><div class="card-body py-2">
          ${fieldList([["Site", r.site], ["URL", readableUrl(r.url)], ["IP de destino", r.ip_destino], ["Porta / serviço", r.servico || r.porta_destino],
                       ["Aplicação", r.aplicacao], ["Categoria", r.categoria], ["Saiu pela interface", r.interface_saida]])}</div></div></div>
        <div class="col-md-4"><div class="card h-100"><div class="card-header py-1 small fw-semibold"><i class="bi bi-bricks"></i> Firewall</div><div class="card-body py-2">
          ${fieldList([["Firewall", r.firewall], ["Regra", r.regra], ["Perfil de segurança", r.politica], ["Ação registrada", r.acao_original], ["Tipo de log", logtypeLabel(r.tipo_log)]])}</div></div></div>
      </div>
      <div class="d-flex flex-wrap gap-2 mt-3">
        <button class="btn btn-sm btn-primary" data-act="copy"><i class="bi bi-clipboard"></i> Copiar resumo para o chamado</button>
        ${repTargets.map((t, i) => `<button class="btn btn-sm btn-outline-primary" data-rep="${esc(t)}"><span class="spinner-border spinner-border-sm spinner-overlay"></span>
          <i class="bi bi-shield-check"></i> ${i ? `Reputação do IP ${esc(t)}` : `Consultar reputação de ${esc(t)}`}</button>`).join("")}
        ${r.ip_origem || r.maquina ? `<button class="btn btn-sm btn-outline-primary" data-act="machine" title="Agente Trend e alertas do Workbench da máquina de origem e do usuário">
          <span class="spinner-border spinner-border-sm spinner-overlay"></span><i class="bi bi-pc-display"></i> Máquina no Vision One</button>` : ""}
        <button class="btn btn-sm btn-outline-secondary ms-auto" data-bs-toggle="collapse" data-bs-target="#rawLog"><i class="bi bi-code"></i> Log original (para N2)</button>
      </div>
      <div class="collapse mt-2" id="rawLog"><pre class="raw">${esc(JSON.stringify(r.log_original || r, null, 2))}</pre></div>
      <div id="logMachine" class="mt-3"></div>
      <div id="logSandbox" class="mt-3"></div>
      <div id="logRep" class="mt-3"></div>`;
    m.querySelector('[data-act="copy"]').addEventListener("click", () => copyText(ticketText(r)));
    m.querySelectorAll("[data-rep]").forEach((b) => b.addEventListener("click", () => reputationInModal(m, r, b.dataset.rep, b)));
    m.querySelector('[data-act="machine"]')?.addEventListener("click", (ev) => machineLookup(m.querySelector("#logMachine"),
      { ip: r.ip_origem, nome: r.maquina, usuario: r.usuario }, ev.currentTarget, { onResult: (d) => { r._maq = d; } }));
    bootstrap.Modal.getOrCreateInstance(m).show();
  }

  // ---- reputação (Vision One) dentro da janela do evento -----------------------------
  async function reputationInModal(m, r, indicator, btn) {
    const box = m.querySelector("#logRep"), oldSb = m.querySelector("#logSandbox");
    // nova consulta: uma análise do Sandbox ainda em andamento para outro indicador deixa de escrever aqui
    const sbBox = oldSb.cloneNode(false); oldSb.replaceWith(sbBox);
    const token = box.dataset.token = String(Math.random());
    busy(btn, true);
    box.innerHTML = `<div class="small text-body-secondary"><span class="spinner-border spinner-border-sm"></span> Consultando ${esc(indicator)} no Vision One...</div>`;
    const show = (rep) => {
      if (!box.isConnected || box.dataset.token !== token) return;
      (r._rep = r._rep || {})[rep.indicador] = rep;  // entra no "Copiar resumo para o chamado"
      renderReputation(box, rep);
      if (rep.tipo !== "ip") sandboxButton(box, rep, sbBox, show);
      box.scrollIntoView({ behavior: "smooth", block: "nearest" });
    };
    // a categoria do FortiGuard do próprio log (filtro web/DNS) entra no veredito do site
    const cat = indicator === r.site ? (r.log_original || {}).catdesc : "";
    try {
      show(await api("/api/v1/reputation", { method: "POST", body: { indicator, type: "auto", ...(cat ? { categoria_fortiguard: cat } : {}) } }));
    } catch (e) {
      if (box.isConnected && box.dataset.token === token) box.innerHTML = `<div class="alert alert-danger small mb-0">Vision One: ${esc(e.message)}</div>`;
    } finally {
      busy(btn, false);
      // o botão desabilitado durante a consulta perde o foco; devolve à janela para o Esc continuar fechando
      if (m.classList.contains("show") && !m.contains(document.activeElement)) m.focus();
    }
  }

  const sandboxEnabled = () => document.body.dataset.sandbox === "1";
  // mantém a categoria do FortiGuard que veio do log quando a reputação é refeita com o Sandbox
  const fortiguardBody = (rep) => (rep.fortiguard?.origem === "evento" && rep.fortiguard.categoria
    ? { categoria_fortiguard: rep.fortiguard.categoria } : {});

  // Cota diária do Sandbox ("" quando o Vision One não informa ou a chave não pode ver a cota)
  async function sandboxQuotaText() {
    try {
      const q = await api("/api/v1/sandbox-quota");
      if (q.restantes === null || q.restantes === undefined) return "";
      const n = (v) => Number(v).toLocaleString("pt-BR");
      return `Cota do Sandbox hoje: ${n(q.restantes)}${q.total ? ` de ${n(q.total)}` : ""} envios disponíveis.`;
    } catch { return ""; }
  }

  // Envia (ou reaproveita) a análise do Sandbox. force: envia de novo mesmo com análise da mesma URL em 24 h.
  async function submitSandbox(indicator, type, extra, force = false) {
    const sub = await api("/api/v1/reputation", { method: "POST", body: { indicator, type, sandbox: true, sandbox_force: force, ...extra } });
    const sb = sub.detalhes?.sandbox;
    if (!sb?.task_id) throw new Error(sub.erros?.sandbox || "O Sandbox não aceitou o envio.");
    return sb;
  }

  // o botão clicado some da tela e leva o foco junto; devolve à janela aberta para o Esc continuar fechando
  function keepModalFocus(el) {
    const modal = el.closest(".modal");
    if (modal?.classList.contains("show") && !modal.contains(document.activeElement)) modal.focus();
  }
  function sandboxButton(box, rep, sbBox, onResult) {
    const card = box.querySelector(".card-body");
    if (!card || rep.detalhes?.sandbox_resultado) return;  // já tem resultado do Sandbox no veredito
    const off = !sandboxEnabled();
    card.insertAdjacentHTML("beforeend", `<div class="mt-2 d-flex flex-wrap align-items-center gap-2"><span title="${off ? "Desabilitado: defina V1_SANDBOX_ENABLED=true em config\\.env"
      : "Envia a URL para análise dinâmica no Sandbox do Vision One. Se a mesma URL foi analisada nas últimas 24 h, o portal reaproveita o resultado e não gasta cota."}">
      <button type="button" class="btn btn-sm btn-outline-primary" data-sandbox ${off ? "disabled" : ""}><span class="spinner-border spinner-border-sm spinner-overlay"></span>
      <i class="bi bi-box-seam"></i> Analisar no Sandbox</button></span><span class="small text-body-secondary" data-quota></span></div>`);
    const b = card.querySelector("[data-sandbox]");
    if (!off) sandboxQuotaText().then((t) => { const q = card.querySelector("[data-quota]"); if (q) q.textContent = t; });
    b.addEventListener("click", async () => {
      busy(b, true);
      try {
        const sb = await submitSandbox(rep.indicador, rep.tipo, fortiguardBody(rep));
        b.closest("div").remove();
        keepModalFocus(sbBox);
        sandboxFlow(sbBox, rep.indicador, rep.tipo, sb.task_id, onResult, fortiguardBody(rep), sb);
      } catch (e) { toast(`Sandbox: ${e.message}`, "warning"); busy(b, false); }
    });
  }

  // Acompanha a análise do Sandbox e, ao terminar, refaz a reputação com o resultado no veredito
  // (as outras fontes não são consultadas de novo). Para sozinho se a janela for fechada.
  // info: resposta do envio; com info.reaproveitado, a análise é de um envio anterior da mesma URL (24 h).
  async function sandboxFlow(box, indicator, type, taskId, onResult, extra = {}, info = null) {
    const reused = !!info?.reaproveitado;
    const when = reused ? `${esc(info.enviado_em)}${info.enviado_por ? ` por ${esc(info.enviado_por)}` : ""}` : "";
    box.innerHTML = reused
      ? `<div class="alert alert-info small mb-0"><span class="spinner-border spinner-border-sm"></span> A mesma URL já está em análise no Sandbox (enviada em ${when}). O portal acompanha essa análise, sem novo envio.</div>`
      : `<div class="alert alert-info small mb-0"><span class="spinner-border spinner-border-sm"></span> Análise no Sandbox em andamento (tarefa ${esc(taskId)}). Pode levar alguns minutos...</div>`;
    keepModalFocus(box);
    for (let i = 0; i < 60; i++) {
      if (!box.isConnected) return;
      try {
        const s = await api(`/api/v1/sandbox/${encodeURIComponent(taskId)}`);
        if (!box.isConnected) return;
        if (s.status === "succeeded") {
          const res = s.resultado;
          box.innerHTML = `<div class="alert alert-${verdictClass(res.risco === "high" ? "Malicioso" : res.risco === "medium" ? "Suspeito" : "")} small mb-0">
            <b>Sandbox concluído:</b> risco ${esc(res.severidade)} · ameaças: ${esc((res.tipos_ameaca || []).join(", ") || "nenhuma")}
            · detecções: ${esc((res.deteccoes || []).join(", ") || "nenhuma")} · concluído em ${esc(res.concluido_em)}
            ${reused ? `<div class="mt-1 d-flex flex-wrap align-items-center gap-2"><span><i class="bi bi-recycle"></i> Resultado reaproveitado da análise enviada em ${when}: não gastou cota nem créditos.</span>
              <button type="button" class="btn btn-sm btn-outline-secondary py-0" data-again title="Envia a URL de novo ao Sandbox (gasta cota e créditos)">
                <span class="spinner-border spinner-border-sm spinner-overlay"></span> Analisar de novo</button></div>` : ""}
            <div class="sb-upd mt-1"><span class="spinner-border spinner-border-sm"></span> Atualizando a reputação com o resultado do Sandbox...</div></div>`;
          box.querySelector("[data-again]")?.addEventListener("click", async (ev) => {
            if (!confirm("Enviar a URL de novo ao Sandbox? Isso gasta cota e créditos do Vision One.")) return;
            const again = ev.currentTarget;
            busy(again, true);
            try {
              const sb = await submitSandbox(indicator, type, extra, true);
              sandboxFlow(box, indicator, type, sb.task_id, onResult, extra, sb);
            } catch (e) { toast(`Sandbox: ${e.message}`, "warning"); busy(again, false); }
          });
          try {
            onResult(await api("/api/v1/reputation", { method: "POST", body: { indicator, type, sandbox: false, sandbox_task: taskId, ...extra } }));
          } catch (e) { toast(e.message, "danger"); }
          box.querySelector(".sb-upd")?.remove();
          return;
        }
        if (s.erro) { box.innerHTML = `<div class="alert alert-warning small mb-0">Sandbox: ${esc(s.erro)}</div>`; return; }
      } catch (e) { box.innerHTML = `<div class="alert alert-warning small mb-0">Sandbox: ${esc(e.message)}</div>`; return; }
      await new Promise((ok) => setTimeout(ok, 10000));
    }
    box.innerHTML = `<div class="alert alert-warning small mb-0">O Sandbox não terminou em 10 minutos. Veja o resultado depois em Threat Intelligence &gt; Sandbox Analysis (tarefa ${esc(taskId)}).</div>`;
  }

  // Cartão de reputação (aba Reputação, Correlação e janela do evento)
  function renderReputation(container, r) {
    const list = (xs) => (xs || []).join(", ") || "-";
    const row = (k, v) => `<dt class="col-sm-3">${k}</dt><dd class="col-sm-9">${v}</dd>`;
    const errs = Object.entries(r.erros || {});
    const fg = r.fortiguard;  // categoria do site no FortiGuard (null para IP)
    let fgRow = "";
    if (fg) {
      const cls = fg.risco === "alto" ? "danger" : fg.risco === "medio" ? "warning" : fg.nao_classificado ? "secondary" : "success";
      const where = fg.origem === "evento" ? "registrada no log" : `visto no log de ${shortTime(fg.visto_em)}`;
      fgRow = row("FortiGuard", fg.categoria
        ? `<span class="badge text-bg-${cls}">${esc(fg.categoria)}</span> <span class="text-body-secondary">${esc(
            fg.risco ? `categoria de risco · ${where}` : fg.nao_classificado ? `site ainda não classificado · ${where}` : where)}</span>`
        : `<span class="text-body-secondary">${esc(fg.erro ? `não consultado (${fg.erro})` : "sem acesso a este site nos logs das últimas 24 h")}</span>`);
    }
    container.innerHTML = `
      <div class="card mb-3 rep-card"><div class="card-body">
        <div class="d-flex flex-wrap align-items-center gap-3 mb-2">
          <div><div class="small text-body-secondary">Indicador</div><div class="fw-semibold">${esc(`${r.indicador} (${r.tipo})`)}</div></div>
          <div><div class="small text-body-secondary">Reputação</div><span class="verdict badge text-bg-${verdictClass(r.reputacao)}">${esc(r.reputacao)}</span></div>
          <div style="min-width:180px"><div class="small text-body-secondary">Risk Score <b>${esc(r.risk_score)}</b>/100</div>
            <div class="risk-bar"><div style="width:${Math.max(3, +r.risk_score || 0)}%;background:${riskColor(+r.risk_score || 0)}"></div></div></div>
          <div class="ms-auto small text-body-secondary">${esc(`Consultado em ${r.consultado_em}${r.cache ? " (cache)" : ""}` +
            (r.periodo ? ` · janela ${r.periodo.inicio} a ${r.periodo.fim}` : ""))}</div>
        </div>
        <dl class="row small mb-0">
          ${row("Categoria", esc(r.categoria ?? "-"))}
          ${fgRow}
          ${row("Severidade", esc(r.severidade ?? "-"))}
          ${row("Tipo da ameaça", esc(list(r.tipo_ameaca)))}
          ${row("IOC relacionados", (r.iocs_relacionados || []).map((i) => `<span class="badge text-bg-secondary me-1">${esc(i.tipo)}: ${esc(i.valor)}</span>`).join("") || "-")}
          ${row("Última análise", esc(r.ultima_analise ?? "-"))}
          ${row("Nível de confiança", esc(r.confianca ?? "-"))}
          ${row("Fonte da informação", esc(list(r.fontes)))}
          ${row("Recomendações", `<ul class="mb-0 ps-3">${(r.recomendacoes || []).map((x) => `<li>${esc(x)}</li>`).join("")}</ul>`)}
        </dl>
        ${errs.length ? `<div class="alert alert-warning small mt-2 mb-0"><b>Fontes que falharam:</b>${errs.map(([k, v]) => `<div>${esc(k)}: ${esc(v)}</div>`).join("")}</div>` : ""}
        <details class="mt-2"><summary class="small">Detalhes técnicos (Suspicious Objects, detecções, alertas)</summary><pre class="raw mt-2">${esc(JSON.stringify(r.detalhes, null, 2))}</pre></details>
      </div></div>`;
  }

  // ---- situação da máquina no Vision One (agente Trend e alertas do Workbench) -------------------
  const MACHINE_STATUS = {
    alerta: ["danger", "bi-exclamation-octagon-fill"], isolada: ["danger", "bi-slash-circle-fill"],
    atencao: ["warning", "bi-exclamation-triangle-fill"], ok: ["success", "bi-shield-fill-check"],
    sem_agente: ["secondary", "bi-question-circle-fill"], erro: ["warning", "bi-exclamation-triangle-fill"],
    info: ["info", "bi-info-circle-fill"],
  };
  const AGENT_CLS = { ativo: "success", desligado: "danger", sem_contato: "warning", desconhecido: "secondary" };
  const SEV_CLS = { critical: "danger", high: "danger", medium: "warning", low: "secondary" };

  function machineTicketLine(d) {
    const ids = (d.alertas || []).map((a) => a.id).join(", ");
    return `Vision One (máquina): ${d.titulo}. ${d.resumo}${ids ? ` Alertas abertos: ${ids}.` : ""}`;
  }

  function renderMachine(container, d) {
    const [cls, icon] = MACHINE_STATUS[d.status] || MACHINE_STATUS.info;
    const row = (k, v) => (v ? `<dt class="col-5 col-sm-4 fw-normal text-body-secondary">${esc(k)}</dt><dd class="col-7 col-sm-8 mb-1">${esc(v)}</dd>` : "");
    const found = { ip: "pelo IP", nome: "pelo nome" };
    const endpoint = (e) => {
      const ag = e.agente || {};
      return `<div class="col-lg-6"><div class="border rounded p-2 h-100">
        <div class="d-flex flex-wrap align-items-center gap-2 mb-2"><i class="bi bi-pc-display"></i><b>${esc(e.nome || e.guid)}</b>
          <span class="badge text-bg-${AGENT_CLS[ag.estado] || "secondary"}">${esc(ag.texto)}</span>
          ${e.isolada ? '<span class="badge text-bg-danger">Isolada da rede</span>' : ""}
          ${e.encontrado_por?.length ? `<span class="small text-body-secondary ms-auto">encontrada ${esc(e.encontrado_por.map((k) => found[k] || k).join(" e "))}</span>` : ""}</div>
        <dl class="row small mb-0">
          ${row("Último contato", ag.ultimo_contato && ag.ultimo_contato + (ag.dias_sem_contato ? ` (há ${ag.dias_sem_contato} dias)` : ""))}
          ${row("Proteção", ag.protecao)}${row("Sensor XDR", ag.sensor)}${row("Isolamento", e.isolamento)}
          ${row("IP", e.ips.join(", "))}${row("MAC", e.macs.join(", "))}${row("Usuário na máquina", e.usuarios.join(", "))}
          ${row("Sistema", e.sistema)}${row("Produtos Trend", e.produtos.join(", "))}${row("Política", e.politica)}
          ${row("Componentes", e.componentes)}
        </dl>
        ${e.erro ? `<div class="small text-warning-emphasis mt-1"><i class="bi bi-exclamation-triangle"></i> ${esc(e.erro)}</div>` : ""}
      </div></div>`;
    };
    const alertItem = (a) => `<li class="list-group-item px-2 py-1 small d-flex flex-wrap gap-2 align-items-center">
        <span class="badge text-bg-${SEV_CLS[a.severidade] || "secondary"}">${esc(a.severidade_texto)}</span>
        <b>${esc(a.modelo)}</b><span class="text-body-secondary">${esc([a.id, a.status, a.criado, a.motivos.join(", ")].filter(Boolean).join(" · "))}</span>
        ${a.link ? `<a class="ms-auto" href="${esc(a.link)}" target="_blank" rel="noopener noreferrer">Abrir no Vision One <i class="bi bi-box-arrow-up-right"></i></a>` : ""}</li>`;
    const p = d.periodo_alertas || {};
    const errs = Object.entries(d.erros || {});
    container.innerHTML = `
      <div class="card mb-3"><div class="card-header py-1 small fw-semibold d-flex align-items-center gap-2">
        <i class="bi bi-pc-display"></i> Máquina no Vision One
        <span class="ms-auto fw-normal text-body-secondary d-none d-sm-inline">Consultado em ${esc(d.consultado_em)}</span>
        <button type="button" class="btn btn-sm btn-link py-0 ms-auto ms-sm-0" data-act="machine-refresh" title="Consultar de novo" aria-label="Consultar de novo">
          <span class="spinner-border spinner-border-sm spinner-overlay"></span><i class="bi bi-arrow-clockwise"></i></button></div>
      <div class="card-body py-2">
        <div class="alert alert-${cls} d-flex gap-2 align-items-start py-2 mb-2"><i class="bi ${icon} fs-4"></i>
          <div><div class="fw-bold">${esc(d.titulo)}</div><div class="small">${esc(d.resumo)}</div></div></div>
        <div class="small mb-2"><span class="fw-semibold text-primary"><i class="bi bi-lightbulb"></i> O que fazer:</span> ${esc(d.orientacao)}</div>
        ${(d.avisos || []).map((a) => `<div class="alert alert-warning small py-1 mb-2">${esc(a)}</div>`).join("")}
        ${d.endpoints.length ? `<div class="row g-2 mb-2">${d.endpoints.map(endpoint).join("")}</div>` : ""}
        <div class="small fw-semibold mt-1">Alertas abertos no Workbench <span class="fw-normal text-body-secondary">(${esc(`${p.inicio} a ${p.fim}`)})</span></div>
        ${d.alertas.length ? `<ul class="list-group mt-1">${d.alertas.map(alertItem).join("")}</ul>`
          : `<div class="small text-body-secondary">${d.erros?.alertas ? "Não consultados." : "Nenhum alerta aberto para a máquina ou o usuário."}</div>`}
        ${d.total_encerrados ? `<details class="mt-1"><summary class="small text-body-secondary">${d.total_encerrados} alerta(s) encerrado(s) no período</summary>
          <ul class="list-group mt-1">${d.alertas_encerrados.map(alertItem).join("")}</ul></details>` : ""}
        ${errs.length ? `<div class="alert alert-warning small mt-2 mb-0"><b>Não foi possível consultar:</b>${errs.map(([k, v]) =>
          `<div>${k === "inventario" ? "Inventário de endpoints" : "Alertas do Workbench"}: ${esc(v)}</div>`).join("")}</div>` : ""}
        ${d.consulta_v1 ? `<div class="small text-body-tertiary mt-2" title="Consulta enviada ao inventário do Vision One (para o N2)">Consulta: ${esc(d.consulta_v1)}</div>` : ""}
      </div></div>`;
  }

  // Consulta a máquina no Vision One e mostra o resultado em "box". onResult recebe cada resultado (também ao atualizar).
  async function machineLookup(box, params, btn, { refresh = false, onResult } = {}) {
    const token = box.dataset.token = String(Math.random());
    if (btn) busy(btn, true);
    if (!refresh) box.innerHTML = `<div class="small text-body-secondary"><span class="spinner-border spinner-border-sm"></span> Consultando a máquina no Vision One...</div>`;
    const qs = new URLSearchParams(Object.entries({ ...params, refresh: refresh ? "true" : "" }).filter(([, v]) => v));
    try {
      const d = await api(`/api/v1/machine?${qs}`);
      if (!box.isConnected || box.dataset.token !== token) return;
      renderMachine(box, d);
      box.querySelector('[data-act="machine-refresh"]').addEventListener("click", (ev) =>
        machineLookup(box, params, ev.currentTarget, { refresh: true, onResult }));
      if (onResult) onResult(d);
      if (!refresh) box.scrollIntoView({ behavior: "smooth", block: "nearest" });
    } catch (e) {
      if (box.isConnected && box.dataset.token === token) box.innerHTML = `<div class="alert alert-danger small mb-0">Vision One: ${esc(e.message)}</div>`;
    } finally {
      if (btn && btn.isConnected) busy(btn, false);
      // dentro da janela do evento: o botão desabilitado perde o foco; devolve à janela para o Esc continuar fechando
      const modal = box.closest(".modal");
      if (modal?.classList.contains("show") && !modal.contains(document.activeElement)) modal.focus();
    }
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
    form.querySelectorAll("input[type=checkbox][name]").forEach((c) => { out[c.name] = c.checked; });
    ["srcport", "dstport", "limit"].forEach((k) => { if (out[k] !== undefined) out[k] = parseInt(out[k], 10); });
    return out;
  }

  // ---- seletor de firewalls (como o do FortiAnalyzer) --------------------------------
  // Nenhum marcado = todos. Cluster HA aparece como um item, com os membros embaixo.
  function devicePicker(box, adomSel) {
    box.innerHTML = `<div class="dropdown device-picker">
        <button type="button" class="btn btn-sm btn-outline-secondary text-body dropdown-toggle w-100 text-start text-truncate" data-bs-toggle="dropdown" data-bs-auto-close="outside">
          <i class="bi bi-hdd-network"></i> <span class="dp-label">Todos os firewalls</span></button>
        <div class="dropdown-menu p-2 dp-menu">
          <input type="search" class="form-control form-control-sm mb-2 dp-search" placeholder="Buscar firewall (nome ou IP)">
          <div class="form-check border-bottom pb-1 mb-1"><input class="form-check-input dp-all" type="checkbox" id="${box.id}-all" checked>
            <label class="form-check-label fw-semibold" for="${box.id}-all">Todos os firewalls <span class="dp-total text-body-secondary"></span></label></div>
          <div class="dp-list"></div>
          <div class="d-flex gap-2 align-items-center border-top pt-2 mt-1">
            <span class="small text-body-secondary dp-count"></span>
            <button type="button" class="btn btn-sm btn-outline-secondary ms-auto dp-clear">Limpar</button>
            <button type="button" class="btn btn-sm btn-primary dp-ok">OK</button></div>
        </div></div>
      <div class="dp-fallback d-none"><input class="form-control form-control-sm" name="devname" placeholder="Nome do firewall (ex.: fw-br-df-reg-bsb213)">
        <div class="form-text">Lista indisponível: o administrador REST precisa de Device Manager (leitura) no FortiAnalyzer.</div></div>
      <div class="dp-hidden"></div>`;
    const $ = (sel) => box.querySelector(sel);
    const toggleBtn = $("[data-bs-toggle]");
    let devs = [], selected = new Set();
    const key = () => `flp-devices-${adomSel.value}`;

    function apply() {
      $(".dp-hidden").innerHTML = [...selected].map((sn) => `<input type="hidden" name="devices" value="${esc(sn)}">`).join("");
      const names = devs.filter((d) => selected.has(d.sn)).map((d) => d.name);
      $(".dp-label").textContent = !names.length ? "Todos os firewalls" : names.length === 1 ? names[0] : `${names.length} firewalls`;
      toggleBtn.title = names.join(", ") || "Todos os firewalls";
      $(".dp-all").checked = !selected.size;
      $(".dp-count").textContent = selected.size ? `${selected.size} selecionado(s)` : "";
      store.set(key(), JSON.stringify([...selected]));
    }
    function draw() {
      const t = $(".dp-search").value.trim().toLowerCase();
      const match = (d) => !t || [d.name, d.ip, d.platform, ...(d.ha_members || []).map((m) => m.name)].some((v) => String(v || "").toLowerCase().includes(t));
      const list = devs.filter(match);
      $(".dp-list").innerHTML = list.map((d) => {
        const ha = d.ha_members && d.ha_members.length;
        const id = `${box.id}-d-${d.sn}`;
        return `<div class="form-check dp-item"><input class="form-check-input" type="checkbox" id="${esc(id)}" value="${esc(d.sn)}" ${selected.has(d.sn) ? "checked" : ""}>
          <label class="form-check-label" for="${esc(id)}"><i class="bi ${ha ? "bi-diagram-3" : "bi-hdd"}"></i> ${esc(d.name)}
          <span class="small text-body-secondary">${esc([ha ? "cluster HA" : "", d.ip].filter(Boolean).join(" · "))}</span></label>
          ${ha ? d.ha_members.map((m) => `<div class="small text-body-secondary ps-3"><i class="bi bi-hdd"></i> [ ${esc(m.name || m.sn)} ]${m.role ? ` ${esc(m.role)}` : ""}</div>`).join("") : ""}</div>`;
      }).join("") || `<div class="small text-body-secondary p-2">Nenhum firewall encontrado.</div>`;
    }
    $(".dp-list").addEventListener("change", (e) => {
      if (e.target.checked) selected.add(e.target.value); else selected.delete(e.target.value);
      apply();
    });
    $(".dp-all").addEventListener("change", () => { selected.clear(); apply(); draw(); });
    $(".dp-clear").addEventListener("click", () => { selected.clear(); apply(); draw(); });
    $(".dp-ok").addEventListener("click", () => bootstrap.Dropdown.getOrCreateInstance(toggleBtn).hide());
    $(".dp-search").addEventListener("input", draw);
    $(".dp-search").addEventListener("keydown", (e) => { if (e.key === "Enter") e.preventDefault(); });
    toggleBtn.addEventListener("shown.bs.dropdown", () => $(".dp-search").focus());

    async function load() {
      try { devs = await api(`/api/faz/adoms/${encodeURIComponent(adomSel.value)}/devices`); } catch { devs = []; }
      $(".device-picker").classList.toggle("d-none", !devs.length);
      $(".dp-fallback").classList.toggle("d-none", !!devs.length);
      $(".dp-total").textContent = devs.length ? `(${devs.length})` : "";
      let saved = [];
      try { saved = JSON.parse(store.get(key(), "[]")); } catch { /* ignora */ }
      selected = new Set(saved.filter((sn) => devs.some((d) => d.sn === sn)));
      apply(); draw();
    }
    adomSel.addEventListener("change", load);
    return { load, names: () => devs.filter((d) => selected.has(d.sn)).map((d) => d.name) };
  }

  async function loadAdomsAndDevices(adomSel, devBox, defaultAdom) {
    try {
      const adoms = await api("/api/faz/adoms");
      adomSel.innerHTML = adoms.map((a) => `<option value="${esc(a.name)}" ${a.name === defaultAdom ? "selected" : ""}>${esc(a.name)}</option>`).join("");
    } catch (e) {
      adomSel.innerHTML = `<option value="${esc(defaultAdom)}">${esc(defaultAdom)}</option>`;
    }
    if (!adomSel.value) adomSel.innerHTML = `<option value="${esc(defaultAdom)}">${esc(defaultAdom)}</option>`;
    if (!devBox) return null;
    const picker = devicePicker(devBox, adomSel);
    await picker.load();
    return picker;
  }

  // ---- filtros adicionados pelo usuário ("Adicionar filtro", como no FortiAnalyzer) --------
  const FILTERS = [
    ["srcip", "IP de origem", "10.55.10.57 ou 10.55.0.0/16"], ["user", "Usuário", "ALUNOS.MACEIO"],
    ["dstip", "IP de destino", "8.8.8.8"], ["hostname", "Site / domínio", "microsoft.com"],
    ["dstport", "Porta de destino", "443"], ["service", "Serviço", "HTTPS"], ["app", "Aplicação", "YouTube"],
    ["action", "Ação", "deny, accept, blocked..."], ["policy", "Regra (nº ou nome)", "14"],
    ["url", "URL (trecho)", "/login"], ["category", "Categoria do site", "Games"], ["profile", "Perfil de segurança", "WebFilter"],
    ["srcport", "Porta de origem", "50000"], ["srcintf", "Interface de entrada", "Rede_Adm"], ["dstintf", "Interface de saída", "Wan01"],
    ["srcname", "Nome da máquina", "NB-ADM-01234"], ["srcmac", "MAC de origem", "00:1a:2b:3c:4d:5e"], ["devname", "Firewall (nome)", "FW-BRASILIA"],
  ];
  const FILTER_LABEL = Object.fromEntries(FILTERS.map(([k, l]) => [k, l]));
  const EXACT = new Set(["srcip", "dstip", "dstport", "srcport", "action", "policy", "srcmac"]);
  const OP_LABEL = { "=": "=", "!=": "≠", "~": "contém" };

  function filterBuilder(box, onChange) {
    box.innerHTML = `<div class="d-flex flex-wrap gap-2 align-items-center">
        <div class="dropdown">
          <button type="button" class="btn btn-sm btn-secondary rounded-pill" data-bs-toggle="dropdown" data-bs-auto-close="outside"><i class="bi bi-plus-lg"></i> Adicionar filtro</button>
          <div class="dropdown-menu p-2 fb-menu"><input type="search" class="form-control form-control-sm mb-1 fb-search" placeholder="Escolha ou digite o filtro">
            <div class="fb-list"></div></div>
        </div>
        <div class="fb-chips d-flex flex-wrap gap-2"></div>
      </div>`;
    const chips = box.querySelector(".fb-chips"), list = box.querySelector(".fb-list"), search = box.querySelector(".fb-search");
    const toggle = box.querySelector("[data-bs-toggle]");
    const drawMenu = () => {
      const t = search.value.trim().toLowerCase();
      const items = FILTERS.filter(([k, l]) => !t || l.toLowerCase().includes(t));
      list.innerHTML = items.map(([k, l]) => `<button type="button" class="dropdown-item small" data-k="${k}">${esc(l)}</button>`).join("")
        || `<div class="small text-body-secondary px-2">Nenhum filtro com esse nome.</div>`;
    };
    function add(field, op, value, focus = true) {
      const chip = document.createElement("div");
      chip.className = "fb-chip input-group input-group-sm";
      chip.dataset.field = field;
      chip.innerHTML = `<span class="input-group-text fw-semibold">${esc(FILTER_LABEL[field] || field)}</span>
        <button type="button" class="btn btn-outline-secondary fb-op" title="Clique para trocar: igual / diferente${EXACT.has(field) ? "" : " / contém"}"></button>
        <input class="form-control fb-val" value="${esc(value || "")}" placeholder="${esc((FILTERS.find(([k]) => k === field) || [])[2] || "")}">
        <button type="button" class="btn btn-outline-secondary fb-del" title="Remover filtro"><i class="bi bi-x-lg"></i></button>`;
      const opBtn = chip.querySelector(".fb-op");
      const setOp = (o) => { chip.dataset.op = o; opBtn.textContent = OP_LABEL[o]; chip.classList.toggle("fb-neg", o === "!="); };
      setOp(op || (EXACT.has(field) ? "=" : "~"));
      opBtn.addEventListener("click", () => {
        const ops = EXACT.has(field) ? ["=", "!="] : ["~", "=", "!="];
        setOp(ops[(ops.indexOf(chip.dataset.op) + 1) % ops.length]);
      });
      chip.querySelector(".fb-del").addEventListener("click", () => { chip.remove(); onChange && onChange(); });
      chip.querySelector(".fb-val").addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); onChange && onChange(); } });
      chips.appendChild(chip);
      if (focus) chip.querySelector(".fb-val").focus();
      return chip;
    }
    list.addEventListener("click", (e) => {
      const b = e.target.closest("[data-k]"); if (!b) return;
      bootstrap.Dropdown.getOrCreateInstance(toggle).hide();
      search.value = ""; drawMenu();
      add(b.dataset.k);
    });
    search.addEventListener("input", drawMenu);
    search.addEventListener("keydown", (e) => {
      if (e.key !== "Enter") return;
      e.preventDefault();
      list.querySelector("[data-k]")?.click();
    });
    toggle.addEventListener("shown.bs.dropdown", () => search.focus());
    drawMenu();
    return {
      add,
      get: () => [...chips.querySelectorAll(".fb-chip")].map((c) => ({ field: c.dataset.field, op: c.dataset.op, value: c.querySelector(".fb-val").value.trim() }))
        .filter((f) => f.value),
      clear: () => { chips.innerHTML = ""; },
      has: (field, op, value) => [...chips.querySelectorAll(".fb-chip")].some((c) => c.dataset.field === field && c.dataset.op === op && c.querySelector(".fb-val").value.trim() === String(value)),
    };
  }

  // ---- período relativo ("Últimos 5 minutos"), recalculado a cada pesquisa ------------------
  function relativePeriod(sel, startEl, endEl, customBox, lastN) {
    // valor do <option>: minutos fixos ("60"), "n:<minutos por unidade>" (últimos N ...) ou "0" (personalizado)
    const UNIT = { 1: "minutos", 60: "horas", 1440: "dias" };
    const minutes = () => {
      if (sel.value.startsWith("n:")) return Math.max(1, +lastN.input.value || 1) * +sel.value.slice(2);
      return +sel.value;
    };
    const sync = () => {
      const isN = sel.value.startsWith("n:");
      lastN?.box.classList.toggle("d-none", !isN);
      if (isN && lastN) lastN.label.textContent = `Quantos ${UNIT[sel.value.slice(2)]}?`;
      const mins = minutes();
      customBox.classList.toggle("d-none", mins !== 0);
      if (mins) {
        const end = new Date();
        startEl.value = toLocalInput(new Date(end.getTime() - mins * 60000));
        endEl.value = toLocalInput(end);
      } else setDefaultPeriod(startEl, endEl, 1);
      store.set("flp-period", sel.value);
    };
    const saved = store.get("flp-period", "");
    if (saved && [...sel.options].some((o) => o.value === saved)) sel.value = saved;
    sel.addEventListener("change", sync);
    lastN?.input.addEventListener("input", sync);
    sync();
    return { refresh: sync };
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
           renderLogTable, exportButtons, renderReputation, sandboxFlow, sandboxQuotaText, machineLookup, machineTicketLine, formData, loadAdomsAndDevices, devicePicker, filterBuilder, relativePeriod, store };
})();
