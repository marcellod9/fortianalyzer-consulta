// Ameaças > Trend inativo: máquinas vistas no firewall da unidade com o agente Trend desligado, sem comunicação ou sem Trend.
window.FLP = window.FLP || {};
FLP.threatsTrend = (() => {
  const esc = FLP.esc;
  const num = (n) => Number(n || 0).toLocaleString("pt-BR");
  const BADGE = { desligado: ["Desligado / offline", "text-bg-danger"], sem_contato: ["Sem comunicação", "text-bg-warning"],
                  sem_trend: ["Sem Trend", "text-bg-secondary"], desconhecido: ["Não informada", "text-bg-light border"],
                  ativo: ["Ativo", "text-bg-success"] };
  let picker = null, last = null;

  const p2 = (n) => String(n).padStart(2, "0");
  const local = (d) => `${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())}T${p2(d.getHours())}:${p2(d.getMinutes())}`;

  function body() {
    const box = document.getElementById("trendDevices"), end = new Date();
    const start = new Date(end.getTime() - +document.getElementById("trendPeriod").value * 60000);
    const devname = (box.querySelector("input[name=devname]") || {}).value || null;
    return { adom: document.getElementById("adom").value, start: local(start), end: local(end),
             devices: [...box.querySelectorAll("input[name=devices]")].map((i) => i.value), devname,
             so_computadores: document.getElementById("trendPcs").checked,
             incluir_ativos: document.getElementById("trendActive").checked };
  }

  function badge(r) {
    const [t, c] = BADGE[r.estado] || [r.estado, "text-bg-light border"];
    const days = r.dias_sem_contato != null && r.estado === "sem_contato" ? ` · ${r.dias_sem_contato} dias` : "";
    // conhecida pelo V1 só como máquina descoberta (Unmanaged endpoints): sem agente
    if (r.estado === "sem_trend" && r.nome_trend) return `<span class="badge ${c}" title="${esc(r.situacao)}">${t}</span><div class="small text-body-secondary">não gerenciada no V1</div>`;
    return `<span class="badge ${c}" title="${esc(r.situacao)}">${t}${days}</span>`;
  }

  // só Windows e Linux podem ter agente Trend: o botão não aparece para AP, impressora, celular etc.
  const checkable = (r) => /windows|linux/i.test(r.sistema || "");

  function rowHtml(r) {
    const user = [r.usuario, r.usuario_trend && r.usuario_trend !== r.usuario ? `Trend: ${r.usuario_trend}` : ""].filter(Boolean);
    return `<tr data-q="${esc([r.maquina, r.ip, r.mac, r.usuario, r.usuario_trend, r.sistema, r.rede, r.grupo].join(" ").toLowerCase())}">
      <td>${badge(r)}</td>
      <td><div class="fw-semibold text-nowrap">${esc(r.maquina || "-")}</div><div class="small text-body-secondary">${esc(r.sistema || "")}</div></td>
      <td class="text-nowrap">${esc(r.ip)}<div class="small text-body-secondary">${esc(r.mac || "")}</div></td>
      <td class="text-break">${user.map((u) => `<div>${esc(u)}</div>`).join("") || "-"}</td>
      <td class="small">${esc(r.rede || "-")}<div class="text-body-secondary">${esc(r.firewall || "")}</div></td>
      <td class="text-nowrap small">${esc(r.ultimo_contato || "-")}</td>
      <td class="text-nowrap small">${esc(String(r.visto || "").slice(0, 16) || "-")}</td>
      <td class="small text-break">${esc(r.grupo || "-")}${r.achado_por ? `<div class="text-body-secondary">pelo ${esc(r.achado_por)}</div>` : ""}</td>
      <td>${checkable(r) ? `<button type="button" class="btn btn-sm btn-outline-secondary text-nowrap" data-check title="Procura a máquina no Vision One agora, pelo nome e pelo IP">
        <i class="bi bi-search"></i> Conferir no V1</button>` : ""}</td>
    </tr>`;
  }

  function render(d) {
    last = d;
    const r = d.resumo, k = FLP.reports.kpi;
    const box = document.getElementById("trendResult");
    box.innerHTML = `
      ${d.avisos.map((a) => `<div class="alert alert-warning small py-2">${esc(a)}</div>`).join("")}
      <div class="row g-2 mb-3">
        ${k("Máquinas vistas", num(r.computadores), "bi-pc-display", "", r.vistas !== r.computadores ? `${num(r.vistas - r.computadores)} fora do filtro Só Windows` : "")}
        ${k("Trend ativo", num(r.ativos), "bi-shield-check", "text-success")}
        ${k("Trend inativo", num(r.inativos), "bi-shield-x", r.inativos ? "text-danger" : "", "desligado ou sem comunicação")}
        ${k("Sem Trend", num(r.sem_trend), "bi-shield-slash", r.sem_trend ? "text-warning" : "", "fora do inventário do Vision One")}
      </div>
      <div class="card"><div class="card-body">
        <div class="d-flex flex-wrap gap-2 align-items-center mb-2">
          <h6 class="mb-0 me-auto"><i class="bi bi-shield-slash"></i> Máquinas para verificar</h6>
          <div class="btn-group btn-group-sm" role="group" id="trendFilter">
            <button type="button" class="btn btn-outline-secondary active" data-f="">Todas</button>
            <button type="button" class="btn btn-outline-secondary" data-f="inativo">Trend inativo</button>
            <button type="button" class="btn btn-outline-secondary" data-f="sem_trend">Sem Trend</button></div>
          <input type="search" class="form-control form-control-sm" style="max-width:16rem" id="trendSearch" placeholder="Buscar máquina, IP, usuário">
        </div>
        <div class="table-responsive" style="max-height:65vh"><table class="table table-sm table-hover align-middle small mb-0">
          <thead class="sticky-top"><tr><th>Trend</th><th>Máquina</th><th>IP / MAC</th><th>Usuário</th><th>Rede / firewall</th>
            <th>Último contato do Trend</th><th>Visto no firewall</th><th>Grupo no Trend</th><th></th></tr></thead>
          <tbody>${d.linhas.map(rowHtml).join("") || `<tr><td colspan="9" class="text-body-secondary">Nenhuma máquina com Trend inativo ou sem Trend nesse período. 🎉</td></tr>`}</tbody>
        </table></div>
        <div class="small text-body-secondary mt-2">Máquinas: ${esc(d.origem)} · inventário do Vision One: ${num(r.inventario)} endpoint(s)
          · período ${esc(d.periodo.inicio.slice(0, 16))} a ${esc(d.periodo.fim.slice(0, 16))}
          ${d.total_linhas > d.linhas.length ? ` · mostrando ${num(d.linhas.length)} de ${num(d.total_linhas)} (exporte para ver todas)` : ""}</div>
      </div></div>`;
    const rows = [...box.querySelectorAll("tbody tr[data-q]")];
    let f = "";
    const apply = () => {
      const t = box.querySelector("#trendSearch").value.trim().toLowerCase();
      rows.forEach((tr, i) => {
        const e = d.linhas[i].estado;
        const okF = !f || (f === "inativo" ? ["desligado", "sem_contato"].includes(e) : e === f);
        tr.classList.toggle("d-none", !(okF && (!t || tr.dataset.q.includes(t))));
      });
    };
    box.querySelector("#trendSearch").addEventListener("input", apply);
    // conferência na hora: a mesma busca de máquina das outras telas (Endpoint Inventory + situação do agente)
    box.querySelector("tbody").addEventListener("click", (ev) => {
      const btn = ev.target.closest("[data-check]");
      if (!btn) return;
      const tr = btn.closest("tr"), r = d.linhas[rows.indexOf(tr)];
      let next = tr.nextElementSibling;
      if (!next || !next.classList.contains("trend-check")) {
        next = document.createElement("tr");
        next.className = "trend-check";
        next.innerHTML = `<td colspan="9"><div></div></td>`;
        tr.after(next);
      }
      FLP.machineLookup(next.querySelector("div"), { ip: r.ip, nome: r.maquina || "", usuario: r.usuario || "" }, btn);
    });
    box.querySelectorAll("#trendFilter button").forEach((b) => b.addEventListener("click", () => {
      box.querySelectorAll("#trendFilter button").forEach((x) => x.classList.toggle("active", x === b));
      f = b.dataset.f; apply();
    }));
    FLP.exportButtons(document.getElementById("trendDownloads"), d.linhas.length ? d.result_id : null);
  }

  async function run(refresh) {
    const btn = document.getElementById("trendBtn");
    FLP.busy(btn, true);
    document.getElementById("trendDownloads").innerHTML = "";
    document.getElementById("trendResult").innerHTML = `<div class="small text-body-secondary"><span class="spinner-border spinner-border-sm"></span>
      Lendo as máquinas do firewall no FortiAnalyzer e o inventário de endpoints do Vision One${refresh ? " (atualizando)" : ""}...</div>`;
    try { render(await FLP.api(`/api/threats/trend-inactive?refresh=${!!refresh}`, { method: "POST", body: body() })); }
    catch (e) { document.getElementById("trendResult").innerHTML = ""; FLP.toast(e.message, "danger"); }
    finally { FLP.busy(btn, false); }
  }

  function init() {
    document.getElementById("tabTrend").addEventListener("shown.bs.tab", async () => {
      if (!picker) { picker = FLP.devicePicker(document.getElementById("trendDevices"), document.getElementById("adom")); await picker.load(); }
    });
    document.getElementById("trendForm").addEventListener("submit", (ev) => { ev.preventDefault(); run(false); });
    document.getElementById("trendRefresh").addEventListener("click", () => run(true));
  }

  return { init, _last: () => last };
})();
