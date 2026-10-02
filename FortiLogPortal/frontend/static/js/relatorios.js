/* FortiLogPortal - Relatórios de acesso com gráficos */
"use strict";
FLP.reports = (() => {
  const esc = FLP.esc;
  const charts = [];
  let last = null;

  // Paleta categórica em ordem fixa (validada para daltonismo), uma versão para cada tema; situação: verde/vermelho
  const PALETTE = {
    light: ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#4a3aa7", "#e34948"],
    dark: ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#008300", "#9085e9", "#e66767"],
  };
  const OTHERS = { light: "#a3a29c", dark: "#6b6a65" };
  const GOOD = "#0ca30c", CRITICAL = "#d03b3b";
  const theme = () => (document.documentElement.getAttribute("data-bs-theme") === "dark" ? "dark" : "light");
  const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
  const num = (n) => Number(n || 0).toLocaleString("pt-BR");
  const pct = (n, t) => (t ? `${((100 * n) / t).toLocaleString("pt-BR", { maximumFractionDigits: 1 })}%` : "-");
  const short = (s, n = 34) => (s && s.length > n ? s.slice(0, n - 1) + "…" : s || "-");
  const timeLabel = (k, g) => `${k.slice(8, 10)}/${k.slice(5, 7)}${g === "hora" ? ` ${k.slice(11, 13)}h` : ""}`;

  const LABELS = { usuario: ["Usuário", "maria.souza (login ou parte dele)"], ip: ["IP ou rede de origem", "10.10.12.34 · 10.10.0.0/16"],
                   site: ["Site ou IP de destino", "facebook.com · youtube.com"], aplicacao: ["Aplicação", "YouTube · Facebook · Tor"] };

  function colorsFor(chart) {
    if (chart.id === "acao") return chart.itens.map(([k]) => (k === "Permitidos" ? GOOD : CRITICAL));
    const pal = PALETTE[theme()];
    return chart.itens.map(([k], i) => (k === "Outros" ? OTHERS[theme()] : pal[i % pal.length]));
  }
  const totalOf = (chart) => (chart.tipo === "pie" || chart.id === "acao" ? chart.itens.reduce((s, [, n]) => s + n, 0) : chart.base);

  function tableHtml(chart) {
    if (chart.tipo === "line") {
      return `<table class="table table-sm small mb-0"><thead><tr><th>${chart.agrupamento === "hora" ? "Horário" : "Dia"}</th>
        <th class="text-end">Permitidos</th><th class="text-end">Bloqueados</th></tr></thead><tbody>
        ${chart.itens.map(([k, a, b]) => `<tr><td>${esc(timeLabel(k, chart.agrupamento))}</td><td class="text-end">${num(a)}</td><td class="text-end">${num(b)}</td></tr>`).join("")}</tbody></table>`;
    }
    const total = totalOf(chart), cols = colorsFor(chart), swatch = chart.tipo === "pie" || chart.id === "acao";
    return `<table class="table table-sm small mb-0"><thead><tr><th>${esc(chart.coluna)}</th><th class="text-end">Registros</th><th class="text-end">%</th></tr></thead><tbody>
      ${chart.itens.map(([k, n], i) => `<tr><td class="text-break">${swatch ? `<span class="rep-swatch" style="background:${cols[i]}"></span>` : ""}${esc(k)}</td>
        <td class="text-end">${num(n)}</td><td class="text-end">${pct(n, total)}</td></tr>`).join("")}</tbody></table>`;
  }

  function card(chart, i) {
    const wide = chart.tipo === "line" || chart.id === "acao";
    let note = `Base: ${num(chart.base)} registros (${esc(chart.fonte)}).`;
    if (chart.sem_valor) note += ` ${num(chart.sem_valor)} sem ${esc(chart.coluna.toLowerCase())} no log.`;
    if (chart.distintos > chart.itens.length && chart.tipo === "bar") note += ` Mostrando ${chart.itens.length} de ${num(chart.distintos)}.`;
    const body = chart.id === "acao" ? meterHtml(chart)
      : `<div class="rep-chart rep-${chart.tipo}"><canvas id="rc${i}" role="img" aria-label="${esc(chart.titulo)}"></canvas></div>`;
    return `<div class="${wide ? "col-12" : "col-xl-6"} rep-card"><div class="card h-100"><div class="card-body">
      <div class="d-flex align-items-start gap-2"><h6 class="mb-0 flex-grow-1">${esc(chart.titulo)}</h6>
        ${chart.id === "acao" ? "" : `<button type="button" class="btn btn-sm btn-link py-0 no-print" data-table="${i}">Ver tabela</button>`}</div>
      <div class="small text-body-secondary mb-2">${note}</div>
      ${body}
      <div class="rep-table mt-2 ${chart.id === "acao" ? "" : "d-none"}" id="rt${i}">${chart.id === "acao" ? "" : tableHtml(chart)}</div>
    </div></div></div>`;
  }

  // Permitidos x bloqueados: barra 100% com rótulos (duas fatias leem melhor numa barra que numa pizza)
  function meterHtml(chart) {
    const total = totalOf(chart), cols = colorsFor(chart);
    return `<div class="rep-meter" role="img" aria-label="${chart.itens.map(([k, n]) => `${k}: ${n}`).join(", ")}">
      ${chart.itens.map(([k, n], i) => `<div style="flex:${n} 1 0;background:${cols[i]}" title="${esc(k)}: ${num(n)} (${pct(n, total)})"></div>`).join("")}</div>
      <div class="d-flex flex-wrap gap-3 mt-2 small">${chart.itens.map(([k, n], i) => `<span><i class="bi ${k === "Permitidos" ? "bi-check-circle-fill" : "bi-x-octagon-fill"}" style="color:${cols[i]}"></i>
        <b>${esc(k)}</b>: ${num(n)} (${pct(n, total)})</span>`).join("")}</div>`;
  }

  function drawCharts(rep) {
    while (charts.length) charts.pop().destroy();
    Chart.defaults.color = css("--bs-secondary-color");
    Chart.defaults.borderColor = css("--bs-border-color-translucent");
    Chart.defaults.font.family = css("--bs-body-font-family");
    const surface = css("--bs-body-bg") || "#fff";
    rep.graficos.forEach((chart, i) => {
      const el = document.getElementById(`rc${i}`);
      if (!el) return;
      const labels = chart.itens.map(([k]) => k);
      const cols = colorsFor(chart);
      let cfg;
      if (chart.tipo === "pie") {
        const total = totalOf(chart);
        cfg = {
          type: "doughnut",
          data: { labels, datasets: [{ data: chart.itens.map(([, n]) => n), backgroundColor: cols, borderColor: surface, borderWidth: 2, hoverOffset: 6 }] },
          options: {
            cutout: "58%", maintainAspectRatio: false,
            plugins: {
              legend: { position: window.innerWidth < 576 ? "bottom" : "right", labels: { boxWidth: 12, generateLabels: (c) => Chart.overrides.doughnut.plugins.legend.labels.generateLabels(c)
                .map((l, j) => ({ ...l, text: `${short(labels[j], 22)} (${pct(chart.itens[j][1], total)})` })) } },
              tooltip: { callbacks: { label: (it) => ` ${num(it.raw)} registros (${pct(it.raw, total)})` } },
            },
          },
          plugins: [{ id: "center", afterDraw(c) {  // total no centro da rosca
            const { ctx, chartArea: a } = c, x = (a.left + a.right) / 2, y = (a.top + a.bottom) / 2;
            ctx.save(); ctx.textAlign = "center"; ctx.fillStyle = css("--bs-body-color");
            ctx.font = `600 18px ${Chart.defaults.font.family}`; ctx.fillText(num(total), x, y + 2);
            ctx.fillStyle = css("--bs-secondary-color"); ctx.font = `12px ${Chart.defaults.font.family}`; ctx.fillText("registros", x, y + 18);
            ctx.restore();
          } }],
        };
      } else if (chart.tipo === "bar") {
        el.parentElement.style.height = `${Math.max(140, chart.itens.length * 28 + 40)}px`;
        cfg = {
          type: "bar",
          data: { labels: labels.map((k) => short(k)), datasets: [{ data: chart.itens.map(([, n]) => n), backgroundColor: PALETTE[theme()][0],
                  borderRadius: 4, borderSkipped: "start", barPercentage: 0.8, categoryPercentage: 0.9 }] },
          options: {
            indexAxis: "y", maintainAspectRatio: false,
            plugins: { legend: { display: false },
                       tooltip: { callbacks: { title: (it) => labels[it[0].dataIndex], label: (it) => ` ${num(it.raw)} registros (${pct(it.raw, chart.base)})` } } },
            scales: { x: { beginAtZero: true, ticks: { precision: 0 }, grid: { color: css("--bs-border-color-translucent") } }, y: { grid: { display: false } } },
          },
        };
      } else {
        cfg = {
          type: "bar",
          data: { labels: chart.rotulos.map((k) => timeLabel(k, chart.agrupamento)), datasets: [
            { label: "Permitidos", data: chart.permitidos, backgroundColor: GOOD, borderColor: surface, borderWidth: { top: 2 }, borderSkipped: false },
            { label: "Bloqueados", data: chart.bloqueados, backgroundColor: CRITICAL, borderColor: surface, borderWidth: { top: 0, bottom: 2 }, borderSkipped: false, borderRadius: { topLeft: 4, topRight: 4 } }] },
          options: {
            maintainAspectRatio: false, interaction: { mode: "index", intersect: false },
            plugins: { legend: { position: "bottom", labels: { boxWidth: 12 } },
                       tooltip: { callbacks: { footer: (its) => `Total: ${num(its.reduce((s, it) => s + it.raw, 0))}` } } },
            scales: { x: { stacked: true, grid: { display: false }, ticks: { maxRotation: 0, autoSkip: true, maxTicksLimit: 14 } },
                      y: { stacked: true, beginAtZero: true, ticks: { precision: 0 }, grid: { color: css("--bs-border-color-translucent") } } },
          },
        };
      }
      if (chart.tipo === "line") {  // série toda zerada (ex.: "somente bloqueios") não entra na legenda
        cfg.data.datasets = cfg.data.datasets.filter((ds) => ds.data.some(Boolean));
      }
      charts.push(new Chart(el, cfg));
    });
  }

  function kpi(label, value, icon, cls = "", sub = "") {
    return `<div class="col-6 col-md-4 col-xl"><div class="card h-100 stat-card"><div class="card-body py-2">
      <div class="label"><i class="bi ${icon}"></i> ${label}</div><div class="value fs-4 ${cls}">${value}</div>
      ${sub ? `<div class="small text-body-secondary">${sub}</div>` : ""}</div></div></div>`;
  }

  // Tabela completa: quem acessou (ou, no relatório de um usuário, o que ele acessou), com busca e ordenação
  const fmtDate = (v) => (v ? `${v.slice(8, 10)}/${v.slice(5, 7)} ${v.slice(11, 16)}` : "");
  function detailHtml(det) {
    if (!det || !det.linhas.length) return "";
    const isUser = det.agrupamento === "usuario";
    let note = isUser ? `${num(det.usuarios)} usuário(s)${det.sem_login ? ` e ${num(det.sem_login)} IP(s) sem login, no fim da lista` : ""}`
      : `${num(det.total)} destino(s)`;
    if (det.total > det.linhas.length) note += `, mostrando os ${num(det.linhas.length)} com mais acessos`;
    note += ".";
    if (det.parciais) note += " * Encontrado numa busca extra: a contagem desse usuário é parcial.";
    if (!det.completo) note += ` <span class="text-warning-emphasis">A lista pode não estar completa (veja o aviso acima).</span>`;
    return `<div class="card mb-3"><div class="card-body">
      <div class="d-flex flex-wrap align-items-center gap-2 mb-1"><h6 class="mb-0 flex-grow-1"><i class="bi ${isUser ? "bi-people" : "bi-globe2"}"></i> ${esc(det.titulo)}</h6>
        <input type="search" class="form-control form-control-sm no-print" id="detSearch" style="max-width:16rem" placeholder="Filtrar a lista"></div>
      <div class="small text-body-secondary mb-2">${note}</div>
      <div class="table-responsive rep-detail"><table class="table table-sm table-hover small mb-0" id="detTable">
        <thead><tr>${det.colunas.map(([k, l]) => `<th class="text-nowrap ${["acessos", "permitidos", "bloqueados"].includes(k) ? "text-end" : ""}" data-sort="${k}" role="button" title="Ordenar">${esc(l)} <i class="bi bi-arrow-down-up small text-body-tertiary no-print"></i></th>`).join("")}</tr></thead>
        <tbody></tbody></table></div></div></div>`;
  }
  function detailBind(det) {
    const table = document.getElementById("detTable");
    if (!table) return;
    let key = "acessos", dir = -1, filter = "";
    const cell = (line, k) => {
      const v = line[k] ?? "";
      if (k === "primeiro" || k === "ultimo") return esc(fmtDate(v));
      if (typeof v === "number") return `${num(v)}${k === "acessos" && line.parcial ? "*" : ""}`;
      if (k === "usuario" && !v.startsWith("(sem login)")) {
        return `<a href="/relatorios?tipo=usuario&valor=${encodeURIComponent(v)}" title="Relatório deste usuário">${esc(v)}</a>`;
      }
      if (k === "destino" && line.tipo === "Site") {
        return `<a href="/relatorios?tipo=site&valor=${encodeURIComponent(v)}" title="Relatório deste site">${esc(v)}</a>`;
      }
      return esc(v);
    };
    const draw = () => {
      const f = filter.toLowerCase();
      const lines = det.linhas.filter((l) => !f || det.colunas.some(([k]) => String(l[k] ?? "").toLowerCase().includes(f)))
        .sort((a, b) => {
          const nl = (l) => String(l.usuario || "").startsWith("(sem login)");
          if (nl(a) !== nl(b)) return nl(a) ? 1 : -1;  // sem login sempre no fim
          return (typeof a[key] === "number" ? a[key] - b[key] : String(a[key]).localeCompare(String(b[key]), "pt-BR")) * dir;
        });
      table.querySelector("tbody").innerHTML = lines.map((l) => `<tr>${det.colunas.map(([k]) =>
        `<td class="${["acessos", "permitidos", "bloqueados"].includes(k) ? "text-end" : ""} ${k === "bloqueados" && l[k] ? "text-danger" : ""}">${cell(l, k)}</td>`).join("")}</tr>`).join("")
        || `<tr><td colspan="${det.colunas.length}" class="text-body-secondary">Nada encontrado com "${esc(filter)}".</td></tr>`;
    };
    table.querySelectorAll("[data-sort]").forEach((th) => th.addEventListener("click", () => {
      dir = key === th.dataset.sort ? -dir : (["acessos", "permitidos", "bloqueados", "primeiro", "ultimo"].includes(th.dataset.sort) ? -1 : 1);
      key = th.dataset.sort;
      draw();
    }));
    document.getElementById("detSearch").addEventListener("input", (ev) => { filter = ev.target.value.trim(); draw(); });
    draw();
  }

  function render(rep) {
    last = rep;
    const box = document.getElementById("report"), r = rep.resumo;
    const fontes = Object.values(rep.fontes).map((f) => f.erro ? `${esc(f.nome)}: não consultado`
      : `${esc(f.nome)}: ${num(f.total)} eventos${f.total > f.lidos ? ` (${num(f.lidos)} analisados)` : ""}`).join(" · ");
    const kinds = { geral: true, usuario: false, ip: true, site: true, aplicacao: true };
    box.innerHTML = `
      <div class="d-flex flex-wrap align-items-baseline gap-2 mb-2">
        <h5 class="mb-0">${esc(rep.titulo)}</h5>
        <span class="small text-body-secondary">${esc(rep.periodo.inicio)} a ${esc(rep.periodo.fim)} · firewall: ${esc(rep.firewall || "Todos")} · gerado em ${esc(rep.gerado_em.slice(0, 16))}${rep.cache ? " (cache)" : ""}</span>
      </div>
      <div class="small text-body-secondary mb-2"><i class="bi bi-database"></i> ${fontes}</div>
      ${rep.aviso_amostra ? `<div class="alert alert-warning small py-2 mb-2"><i class="bi bi-info-circle"></i> ${esc(rep.aviso_amostra)}</div>` : ""}
      ${rep.aviso ? `<div class="alert alert-warning small py-2 mb-2">${esc(rep.aviso)}</div>` : ""}
      <div class="row g-2 mb-3">
        ${kpi("Eventos", num(r.eventos), "bi-list-ul", "", rep.amostra ? `${num(r.lidos)} analisados` : "")}
        ${kpi("Bloqueados", num(r.bloqueados), "bi-x-octagon", "text-danger", rep.amostra ? `nos ${num(r.lidos)} analisados` : "")}
        ${kinds[rep.tipo] ? kpi("Usuários", num(r.usuarios), "bi-people") : kpi("IPs de origem", num(r.ips), "bi-pc-display")}
        ${rep.tipo !== "aplicacao" ? kpi("Sites", num(r.sites), "bi-globe2") : ""}
        ${rep.tipo !== "site" ? kpi("Aplicações", num(r.aplicacoes), "bi-app-indicator") : ""}
      </div>
      ${rep.tipo !== "geral" ? detailHtml(rep.detalhe) : ""}
      ${rep.graficos.length ? `<div class="row g-3">${rep.graficos.map(card).join("")}</div>`
        : `<div class="alert alert-secondary">Nenhum evento no período para os filtros escolhidos. Aumente o período, confira o filtro
            ou escolha outro firewall.</div>`}
      ${rep.tipo === "geral" ? `<div class="mt-3">${detailHtml(rep.detalhe)}</div>` : ""}`;
    detailBind(rep.detalhe);
    box.querySelectorAll("[data-table]").forEach((b) => b.addEventListener("click", () => {
      const t = document.getElementById(`rt${b.dataset.table}`);
      t.classList.toggle("d-none");
      b.textContent = t.classList.contains("d-none") ? "Ver tabela" : "Ocultar tabela";
    }));
    drawCharts(rep);
    const dl = document.getElementById("downloads");
    dl.innerHTML = `<button type="button" class="btn btn-sm btn-outline-danger" data-fmt="pdf"><i class="bi bi-file-earmark-pdf"></i> PDF</button>
      <button type="button" class="btn btn-sm btn-outline-success" data-fmt="xlsx"><i class="bi bi-file-earmark-excel"></i> Excel</button>
      <button type="button" class="btn btn-sm btn-outline-secondary" data-act="print"><i class="bi bi-printer"></i> Imprimir</button>`;
    dl.querySelectorAll("[data-fmt]").forEach((b) => b.addEventListener("click", async () => {
      FLP.busy(b, true);
      try { await FLP.download(`/api/reports/${rep.report_id}.${b.dataset.fmt}`); } catch (e) { FLP.toast(e.message, "danger"); }
      finally { FLP.busy(b, false); }
    }));
    dl.querySelector("[data-act=print]").addEventListener("click", () => window.print());
  }

  function init(defaultAdom) {
    const form = document.getElementById("form"), btn = document.getElementById("btn");
    const tipo = document.getElementById("tipo"), valor = document.getElementById("valor");
    const period = FLP.relativePeriod(document.getElementById("period"), document.getElementById("start"),
                                      document.getElementById("end"), document.getElementById("custom"),
                                      { box: document.getElementById("lastN"), input: document.getElementById("lastNValue"),
                                        label: document.getElementById("lastNLabel") });
    FLP.loadAdomsAndDevices(document.getElementById("adom"), document.getElementById("devices"), defaultAdom);
    const syncType = () => {
      const l = LABELS[tipo.value];
      document.getElementById("valorBox").classList.toggle("d-none", !l);
      valor.required = !!l;
      if (l) { document.getElementById("valorLabel").textContent = l[0]; valor.placeholder = l[1]; }
    };
    tipo.addEventListener("change", () => { syncType(); if (LABELS[tipo.value]) valor.focus(); });
    syncType();
    // atalhos de outras telas: /relatorios?tipo=usuario&valor=maria.souza
    const qs = new URLSearchParams(location.search);
    if (qs.get("tipo") && [...tipo.options].some((o) => o.value === qs.get("tipo"))) {
      tipo.value = qs.get("tipo"); syncType(); valor.value = qs.get("valor") || "";
    }
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      period.refresh();
      const body = FLP.formData(form);
      body.top = +body.top;
      if (body.tipo === "geral") delete body.valor;
      FLP.busy(btn, true);
      document.getElementById("downloads").innerHTML = "";
      document.getElementById("report").innerHTML = `<div class="small text-body-secondary"><span class="spinner-border spinner-border-sm"></span>
        Consultando o FortiAnalyzer (filtro web e controle de aplicações) e montando os gráficos...</div>`;
      try { render(await FLP.api("/api/reports", { method: "POST", body })); }
      catch (e) { document.getElementById("report").innerHTML = ""; FLP.toast(e.message, "danger"); }
      finally { FLP.busy(btn, false); }
    });
    // o tema escuro/claro troca as cores dos gráficos
    new MutationObserver(() => last && drawCharts(last)).observe(document.documentElement, { attributes: true, attributeFilter: ["data-bs-theme"] });
    if (qs.get("tipo") && (qs.get("tipo") === "geral" || valor.value)) form.requestSubmit();
  }

  return { init };
})();
