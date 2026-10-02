/* FortiLogPortal - Ameaças: máquinas comprometidas (IOC) e ranking de ameaças */
"use strict";
FLP.threats = (() => {
  const esc = FLP.esc;
  const num = (n) => Number(n || 0).toLocaleString("pt-BR");
  const fmtDate = (v) => (v ? `${v.slice(8, 10)}/${v.slice(5, 7)} ${v.slice(11, 16)}` : "-");
  const SEV = { critical: ["Crítica", "text-bg-danger"], high: ["Alta", "sev-high"], medium: ["Média", "text-bg-warning"],
                low: ["Baixa", "text-bg-secondary"], info: ["Informativa", "text-bg-light border"], information: ["Informativa", "text-bg-light border"] };
  const sevBadge = (s) => { const [t, c] = SEV[s] || ["-", "text-bg-light border"]; return `<span class="badge ${c}">${t}</span>`; };
  let last = null, canReports = false;

  function machineCell(ip, name) {
    return `${name ? `<div class="fw-semibold">${esc(name)}</div>` : ""}<div class="${name ? "small text-body-secondary" : ""}">${esc(ip || "-")}</div>`;
  }

  function actions(ip, name, user) {
    const v1 = `<button type="button" class="btn btn-sm btn-outline-primary py-0 text-nowrap" data-v1 data-ip="${esc(ip)}" data-nome="${esc(name || "")}"
      data-usuario="${esc(user || "")}" title="Agente Trend, isolamento e alertas da máquina no Vision One"><i class="bi bi-pc-display"></i> Vision One</button>`;
    const rep = canReports && ip ? `<a class="btn btn-sm btn-outline-secondary py-0" href="/relatorios?tipo=ip&valor=${encodeURIComponent(ip)}"
      title="Relatório de acessos deste IP"><i class="bi bi-pie-chart"></i></a>` : "";
    return `<div class="d-flex gap-1 justify-content-end">${v1}${rep}</div>`;
  }

  function compromisedHtml(c) {
    if (c.erro) {
      return `<div class="alert alert-warning small"><i class="bi bi-shield-exclamation"></i> <b>Máquinas comprometidas (IOC):</b> ${esc(c.erro)}</div>`;
    }
    const rows = c.maquinas.map((h) => `<tr class="${h.reconhecido ? "" : "table-danger-subtle"}">
        <td>${machineCell(h.ip, h.maquina)}</td><td>${esc(h.usuarios.join(", ") || "-")}</td>
        <td>${h.ameacas.map((t) => `<span class="badge text-bg-dark me-1">${esc(t)}</span>`).join("")}
            ${h.dominios.length ? `<div class="small text-body-secondary text-break">${esc(h.dominios.join(", "))}</div>` : ""}
            ${!h.ameacas.length && !h.dominios.length ? `<span class="small">${esc(h.assunto)}</span>` : ""}</td>
        <td>${sevBadge(h.pior)}</td><td class="text-end">${num(h.alertas)}</td><td class="text-nowrap">${fmtDate(h.ultimo)}</td>
        <td class="small">${esc(h.regras.join(", "))}<div class="text-body-secondary">${esc(h.firewall)}</div></td>
        <td>${h.reconhecido ? `<span class="badge text-bg-success">ACK</span>` : `<span class="badge text-bg-danger">pendente</span>`}</td>
        <td>${actions(h.ip, h.maquina, h.usuarios[0])}</td></tr>
        <tr class="d-none v1-row"><td colspan="9"><div class="v1-box"></div></td></tr>`).join("");
    return `<div class="card mb-3 border-danger-subtle"><div class="card-body">
      <h6 class="mb-1"><i class="bi bi-shield-exclamation text-danger"></i> Máquinas comprometidas (IOC)</h6>
      <div class="small text-body-secondary mb-2">Alertas de IOC e botnet do Event Monitor do FortiAnalyzer (${num(c.alertas)} alerta(s)${c.mais ? `, lidos os ${num(c.alertas_lidos)} mais recentes` : ""}).
        Sem ACK aparecem primeiro: confira a máquina no Vision One e acione a Segurança.</div>
      ${c.maquinas.length ? `<div class="table-responsive"><table class="table table-sm small align-middle mb-0">
        <thead><tr><th>Máquina</th><th>Usuário</th><th>Ameaça / destino</th><th>Severidade</th><th class="text-end">Alertas</th><th>Último</th><th>Regra / firewall</th><th>ACK</th><th></th></tr></thead>
        <tbody>${rows}</tbody></table></div>`
        : `<div class="alert alert-success small mb-0"><i class="bi bi-check-circle"></i> Nenhuma máquina com alerta de IOC ou botnet no período.</div>`}
    </div></div>`;
  }

  function threatsHtml(t) {
    const rows = t.linhas.map((x) => `<tr><td class="text-break">${esc(x.ameaca)}</td><td>${esc(x.tipo)}</td><td>${sevBadge(x.severidade)}</td>
      <td class="text-end">${num(x.eventos)}</td><td class="text-end ${x.permitidos ? "text-danger fw-semibold" : ""}">${num(x.permitidos)}</td>
      <td class="text-end">${num(x.maquinas)}</td><td class="text-end">${num(x.usuarios)}</td><td class="text-nowrap">${fmtDate(x.ultimo)}</td></tr>`).join("");
    return `<div class="card mb-3"><div class="card-body">
      <div class="d-flex align-items-center gap-2 mb-1"><h6 class="mb-0 me-auto"><i class="bi bi-list-ol"></i> Ameaças</h6>
        <input class="form-control form-control-sm" style="max-width:16rem" data-search="thr" placeholder="Filtrar ameaça ou tipo"></div>
      <div class="small text-body-secondary mb-2">${num(t.total)} ameaça(s) diferente(s). As que passaram pelo firewall (não bloqueadas) vêm primeiro.</div>
      <div class="table-responsive" style="max-height:420px"><table class="table table-sm small align-middle mb-0" id="thr">
        <thead class="sticky-top"><tr><th>Ameaça</th><th>Tipo</th><th>Severidade</th><th class="text-end">Eventos</th><th class="text-end">Não bloqueados</th>
        <th class="text-end">Máquinas</th><th class="text-end">Usuários</th><th>Último</th></tr></thead><tbody>${rows ||
        `<tr><td colspan="8" class="text-body-secondary">Nenhuma ameaça nos logs do período.</td></tr>`}</tbody></table></div>
    </div></div>`;
  }

  function hostsHtml(hosts) {
    const rows = hosts.map((h) => `<tr><td>${machineCell(h.ip, h.maquina)}</td><td>${esc(h.usuarios.join(", ") || "-")}</td>
      <td class="small text-break">${esc(h.principais.join(" · "))}${h.qtd_ameacas > h.principais.length ? ` <span class="text-body-secondary">+${h.qtd_ameacas - h.principais.length}</span>` : ""}</td>
      <td>${sevBadge(h.pior)}</td><td class="text-end">${num(h.eventos)}</td><td class="text-end ${h.permitidos ? "text-danger fw-semibold" : ""}">${num(h.permitidos)}</td>
      <td class="text-nowrap">${fmtDate(h.ultimo)}</td><td>${actions(h.ip, h.maquina, h.usuarios[0])}</td></tr>
      <tr class="d-none v1-row"><td colspan="8"><div class="v1-box"></div></td></tr>`).join("");
    return `<div class="card mb-3"><div class="card-body">
      <div class="d-flex align-items-center gap-2 mb-1"><h6 class="mb-0 me-auto"><i class="bi bi-pc-display-horizontal"></i> Máquinas afetadas</h6>
        <input class="form-control form-control-sm" style="max-width:16rem" data-search="hst" placeholder="Filtrar máquina, IP ou usuário"></div>
      <div class="small text-body-secondary mb-2">Máquina de origem da ameaça (no IPS de entrada, a máquina atacada). Quem teve ameaça não bloqueada vem primeiro.</div>
      <div class="table-responsive" style="max-height:420px"><table class="table table-sm small align-middle mb-0" id="hst">
        <thead class="sticky-top"><tr><th>Máquina</th><th>Usuário</th><th>Principais ameaças</th><th>Pior severidade</th><th class="text-end">Eventos</th>
        <th class="text-end">Não bloqueados</th><th>Último</th><th></th></tr></thead><tbody>${rows ||
        `<tr><td colspan="8" class="text-body-secondary">Nenhuma máquina afetada no período.</td></tr>`}</tbody></table></div>
    </div></div>`;
  }

  function bind(box) {
    box.querySelectorAll("[data-search]").forEach((inp) => inp.addEventListener("input", () => {
      const q = inp.value.trim().toLowerCase();
      document.querySelectorAll(`#${inp.dataset.search} tbody tr:not(.v1-row)`).forEach((tr) => {
        tr.classList.toggle("d-none", !!q && !tr.textContent.toLowerCase().includes(q));
        const next = tr.nextElementSibling;
        if (next && next.classList.contains("v1-row") && q) next.classList.add("d-none");
      });
    }));
    box.querySelectorAll("[data-v1]").forEach((b) => b.addEventListener("click", () => {
      const row = b.closest("tr").nextElementSibling;
      const open = row.classList.toggle("d-none") === false;
      if (open && !row.dataset.loaded) {
        row.dataset.loaded = "1";
        FLP.machineLookup(row.querySelector(".v1-box"), { ip: b.dataset.ip, nome: b.dataset.nome, usuario: b.dataset.usuario }, b);
      }
    }));
  }

  function render(d) {
    last = d;
    const box = document.getElementById("result"), r = d.resumo;
    const fontes = Object.values(d.fontes).map((f) => f.erro ? `${esc(f.nome)}: não consultado`
      : `${esc(f.nome)}: ${f.mais ? "≥ " : ""}${num(f.total)}`).join(" · ");
    const erros = Object.values(d.fontes).filter((f) => f.erro);
    box.innerHTML = `
      <div class="small text-body-secondary mb-2"><i class="bi bi-calendar3"></i> ${esc(d.periodo.inicio)} a ${esc(d.periodo.fim)}
        · gerado em ${esc(d.gerado_em.slice(0, 16))}${d.cache ? " (cache)" : ""}<br><i class="bi bi-database"></i> ${fontes}</div>
      ${d.amostra ? `<div class="alert alert-warning small py-2"><i class="bi bi-info-circle"></i> Alguma fonte tem mais eventos do que o portal lê
        (${num(d.limite_amostra)} por fonte, os mais recentes). Para o período inteiro, diminua o período ou escolha o firewall.</div>` : ""}
      ${erros.length ? `<div class="alert alert-warning small py-2">Não foi possível consultar: ${erros.map((f) => `${esc(f.nome)} (${esc(f.erro)})`).join("; ")}</div>` : ""}
      <div class="row g-2 mb-3">
        ${FLP.reports.kpi("Máquinas com IOC", d.comprometidas.erro ? "-" : num(r.comprometidas), "bi-shield-exclamation", r.comprometidas ? "text-danger" : "")}
        ${FLP.reports.kpi("Eventos de ameaça", num(r.eventos), "bi-bug")}
        ${FLP.reports.kpi("Não bloqueados", num(r.nao_bloqueados), "bi-exclamation-triangle", r.nao_bloqueados ? "text-danger" : "", "detectados, mas passaram")}
        ${FLP.reports.kpi("Máquinas afetadas", num(r.maquinas), "bi-pc-display")}
        ${FLP.reports.kpi("Usuários afetados", num(r.usuarios), "bi-people")}
      </div>
      ${compromisedHtml(d.comprometidas)}
      ${d.graficos.length ? `<div class="row g-3 mb-3">${d.graficos.map(FLP.reports.card).join("")}</div>` : ""}
      ${threatsHtml(d.ameacas)}
      ${hostsHtml(d.maquinas)}`;
    bind(box);
    box.querySelectorAll("[data-table]").forEach((b) => b.addEventListener("click", () => {
      const t = document.getElementById(`rt${b.dataset.table}`);
      t.classList.toggle("d-none");
      b.textContent = t.classList.contains("d-none") ? "Ver tabela" : "Ocultar tabela";
    }));
    FLP.reports.drawCharts(d);
    FLP.exportButtons(document.getElementById("downloads"), d.eventos_exportaveis ? d.result_id : null);
  }

  function init(defaultAdom, reportsAllowed) {
    canReports = reportsAllowed;
    const form = document.getElementById("form"), btn = document.getElementById("btn");
    const period = FLP.relativePeriod(document.getElementById("period"), document.getElementById("start"),
                                      document.getElementById("end"), document.getElementById("custom"),
                                      { box: document.getElementById("lastN"), input: document.getElementById("lastNValue"),
                                        label: document.getElementById("lastNLabel") });
    FLP.loadAdomsAndDevices(document.getElementById("adom"), document.getElementById("devices"), defaultAdom);
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      period.refresh();
      const body = FLP.formData(form);
      FLP.busy(btn, true);
      document.getElementById("downloads").innerHTML = "";
      document.getElementById("result").innerHTML = `<div class="small text-body-secondary"><span class="spinner-border spinner-border-sm"></span>
        Consultando o Event Monitor e os logs de IPS, antivírus, filtro web, aplicações e DNS no FortiAnalyzer...</div>`;
      try { render(await FLP.api("/api/threats", { method: "POST", body })); }
      catch (e) { document.getElementById("result").innerHTML = ""; FLP.toast(e.message, "danger"); }
      finally { FLP.busy(btn, false); }
    });
    new MutationObserver(() => last && FLP.reports.drawCharts(last)).observe(document.documentElement, { attributes: true, attributeFilter: ["data-bs-theme"] });
  }

  return { init };
})();
