/* FortiLogPortal - dashboard */
"use strict";
(() => {
  const charts = {};
  const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();

  function themeDefaults() {
    Chart.defaults.color = css("--bs-body-color");
    Chart.defaults.borderColor = css("--bs-border-color");
  }

  function bar(id, pairs, color) {
    const el = document.getElementById(id);
    if (charts[id]) charts[id].destroy();
    const labels = pairs.map(([k]) => (k && k.length > 38 ? k.slice(0, 36) + "…" : k || "-"));
    charts[id] = new Chart(el, {
      type: "bar",
      data: { labels, datasets: [{ data: pairs.map(([, n]) => n), backgroundColor: color, borderRadius: 4 }] },
      options: { indexAxis: "y", plugins: { legend: { display: false }, tooltip: { callbacks: { title: (it) => pairs[it[0].dataIndex][0] } } },
                 scales: { x: { beginAtZero: true, ticks: { precision: 0 } } }, maintainAspectRatio: false },
    });
    el.parentElement.style.height = Math.max(180, pairs.length * 26 + 60) + "px";
  }

  function list(id, items, fmt) {
    document.getElementById(id).innerHTML = items.map(fmt).join("") || `<li><span class="text-body-secondary">Nenhum registro</span></li>`;
  }

  async function loadFaz(refresh = false) {
    const btn = document.getElementById("refresh");
    const hours = document.getElementById("hours").value;
    const msg = document.getElementById("fazMsg");
    FLP.busy(btn, true);
    msg.textContent = "Consultando bloqueios no FortiAnalyzer...";
    try {
      const d = await FLP.api(`/api/dashboard/faz?hours=${hours}${refresh ? "&refresh=true" : ""}`);
      document.getElementById("s_faz").textContent = d.total_bloqueios.toLocaleString("pt-BR");
      document.getElementById("s_horas").textContent = d.periodo_horas;
      bar("c_sites", d.sites_mais_bloqueados, "#c0392b");
      bar("c_users", d.usuarios_mais_bloqueados, "#d35400");
      bar("c_rules", d.regras_mais_acionadas, "#2c7be5");
      bar("c_fws", d.firewalls_mais_eventos, "#6f42c1");
      const errs = Object.entries(d.erros || {}).map(([k, v]) => `${k}: ${v}`).join(" | ");
      msg.textContent = `Amostra de ${d.amostra} bloqueios mais recentes · atualizado em ${d.atualizado_em}${d.cache ? " (cache)" : ""}` + (errs ? ` · avisos: ${errs}` : "");
    } catch (e) {
      msg.innerHTML = `<span class="text-danger">FortiAnalyzer: ${FLP.esc(e.message)}</span>`;
    } finally { FLP.busy(btn, false); }
  }

  async function loadLocal() {
    const d = await FLP.api("/api/dashboard/local");
    const s = d.estatisticas, v = d.visionone;
    document.getElementById("s_consultas").textContent = s.total_consultas.toLocaleString("pt-BR");
    document.getElementById("s_bloqueios").textContent = s.total_bloqueios.toLocaleString("pt-BR");
    document.getElementById("s_iocs").textContent = s.total_iocs.toLocaleString("pt-BR");
    const ioc = (i) => `<li><span title="${FLP.esc(i.indicator)}">${FLP.esc(i.indicator)}</span><span class="badge text-bg-${i.risk_score >= 80 ? "danger" : "warning"}">${i.risk_score}</span></li>`;
    list("v_dom", v.dominios_maliciosos, ioc);
    list("v_ip", v.ips_maliciosos, ioc);
    list("v_url", v.urls_risco, ioc);
    list("v_last", v.ultimas, (i) => `<li><span title="${FLP.esc(i.ts)}">${FLP.esc(i.indicator)}</span><span class="badge text-bg-${FLP.verdictClass(i.verdict)}">${FLP.esc(i.verdict)}</span></li>`);
    if (charts.daily) charts.daily.destroy();
    charts.daily = new Chart(document.getElementById("c_daily"), {
      type: "line",
      data: {
        labels: s.historico_diario.map((x) => x.dia.slice(5).split("-").reverse().join("/")),
        datasets: [
          { label: "Consultas", data: s.historico_diario.map((x) => x.consultas), borderColor: "#2c7be5", backgroundColor: "#2c7be5", tension: .3 },
          { label: "Bloqueios encontrados", data: s.historico_diario.map((x) => x.bloqueios), borderColor: "#c0392b", backgroundColor: "#c0392b", tension: .3 },
        ],
      },
      options: { scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } },
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    themeDefaults();
    loadLocal().catch((e) => FLP.toast(e.message, "danger"));
    loadFaz();
    document.getElementById("refresh").addEventListener("click", () => loadFaz(true));
    document.getElementById("hours").addEventListener("change", () => loadFaz());
    // recria os gráficos com as cores do novo tema (dados vêm do cache)
    document.addEventListener("flp-theme", () => { themeDefaults(); loadLocal().catch(() => {}); loadFaz(); });
  });
})();
