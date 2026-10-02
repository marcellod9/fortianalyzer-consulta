// Ameaças > Mapa em tempo real: repete a consulta dos últimos minutos e anima cada evento novo como um arco
// entre o firewall e o país do outro lado (como o Threat Map do FortiAnalyzer).
window.FLP = window.FLP || {};
FLP.threatsLive = (() => {
  const esc = FLP.esc;
  const SEV = { critical: ["Crítica", "#e66767"], high: ["Alta", "#ff8a4c"], medium: ["Média", "#f2c14e"],
                low: ["Baixa", "#7cc4ff"], info: ["Informativa", "#7cc4ff"], information: ["Informativa", "#7cc4ff"] };
  const sev = (s) => SEV[s] || ["-", "#7cc4ff"];
  const FEED_MAX = 12, SEEN_MAX = 5000, ARC_MS = 1600, FADE_MS = 2600, FIRST_MIN = 10, NEXT_MIN = 5;
  const NS = "http://www.w3.org/2000/svg";

  let el = {}, world = null, centroid = {}, fw = {}, fwDefault = null, picker = null;
  let active = false, paused = false, pollTimer = null, playTimer = null, first = true, busy = false, generation = 0;
  let seen = new Set(), seenOrder = [], queue = [];
  let stats = { eventos: 0, bloqueados: 0, paises: {} };

  // ---- projeção Natural Earth I (a mesma usada para gerar world-110m.json) -----------------------
  function project(lat, lon) {
    const P = world.proj, l = (lon * Math.PI) / 180, p = (lat * Math.PI) / 180, p2 = p * p, p4 = p2 * p2;
    const x = l * (0.8707 - 0.131979 * p2 + p4 * (-0.013791 + p4 * (0.003971 * p2 - 0.001529 * p4)));
    const y = p * (1.007226 + p2 * (0.015085 + p4 * (-0.044475 + 0.028874 * p2 - 0.005916 * p4)));
    return [(x - P.x0) * P.k, (P.y0 - y) * P.k];
  }

  async function loadWorld() {
    if (world) return;
    world = await (await fetch("/static/vendor/worldmap/world-110m.json?v=2")).json();
    world.paises.forEach((p) => { centroid[p.n] = p.c; });
    fwDefault = centroid.Brazil || [world.w * 0.37, world.h * 0.69];
    el.map.insertAdjacentHTML("afterbegin", `<svg viewBox="0 0 ${world.w} ${world.h}" role="img" aria-label="Mapa de ameaças em tempo real">
      <g class="live-land">${world.paises.map((p) => `<path d="${p.d}" data-n="${esc(p.n)}"></path>`).join("")}</g>
      <g class="live-arcs"></g><g class="live-fws"></g></svg>`);
    el.svg = el.map.querySelector("svg");
    el.arcs = el.svg.querySelector(".live-arcs");
    el.fws = el.svg.querySelector(".live-fws");
  }

  // posição de cada firewall: latitude/longitude cadastradas no FortiGate (Device Manager); sem elas, Brasil
  async function loadFirewalls() {
    fw = {};
    let devs = [];
    try { devs = await FLP.api(`/api/faz/adoms/${encodeURIComponent(el.adom.value)}/devices`); } catch { devs = []; }
    devs.forEach((d) => {
      const pos = d.lat != null && d.lon != null ? project(d.lat, d.lon) : null;
      const item = { name: d.name, pos, sn: d.sn };
      fw[d.name] = item;
      (d.ha_members || []).forEach((m) => { if (m.name) fw[m.name] = item; });
    });
    drawFirewalls();
  }

  const fwPos = (name) => (fw[name] && fw[name].pos) || fwDefault;

  function drawFirewalls() {
    const selected = new Set([...el.devices.querySelectorAll("input[name=devices]")].map((i) => i.value));
    const items = [...new Set(Object.values(fw))].filter((d) => !selected.size || selected.has(d.sn));
    const byPos = {};
    items.forEach((d) => { const p = d.pos || fwDefault, k = p.map((v) => v.toFixed(0)).join(","); (byPos[k] = byPos[k] || { p, names: [] }).names.push(d.name); });
    if (!items.length) byPos.x = { p: fwDefault, names: ["Firewall"] };
    el.fws.innerHTML = Object.values(byPos).map(({ p, names }) => `<g transform="translate(${p[0].toFixed(1)},${p[1].toFixed(1)})">
      <title>${esc(names.slice(0, 15).join(", ") + (names.length > 15 ? ` e mais ${names.length - 15}` : ""))}</title>
      <circle r="9" class="live-fw-halo"></circle><circle r="4.5" class="live-fw"></circle></g>`).join("");
  }

  // ---- consulta periódica -----------------------------------------------------------------------
  const every = () => +el.every.value * 1000;
  const speed = () => +el.speed.value || 1;

  // uma fonte por vez: o FAZ recusa buscas simultâneas do mesmo admin, e assim cada resultado já aparece no mapa
  const SOURCES = [["ips", "IPS"], ["botnet", "botnet"], ["virus", "antivírus"], ["malicioso", "sites maliciosos"],
                   ["phishing", "phishing"], ["dns", "DNS"]];
  const OVERLAP_MS = 60000;  // margem para logs que chegam atrasados ao FAZ
  const p2 = (n) => String(n).padStart(2, "0");
  const local = (d) => `${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())}T${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}`;
  const parse = (s) => { const d = new Date(String(s || "").replace(" ", "T")); return isNaN(d) ? null : d; };
  let newest = {}, queried = new Set();

  function body(sid, end) {
    // depois da primeira, a busca começa no evento mais novo já visto da fonte (janela curta = busca rápida no FAZ)
    let from = end.getTime() - (queried.has(sid) ? NEXT_MIN : FIRST_MIN) * 60000;
    if (newest[sid]) from = Math.min(end.getTime() - OVERLAP_MS, Math.max(from, newest[sid].getTime() - OVERLAP_MS));
    const devices = [...el.devices.querySelectorAll("input[name=devices]")].map((i) => i.value);
    const devname = (el.devices.querySelector("input[name=devname]") || {}).value || null;
    return { adom: el.adom.value, devices, devname: devname || null, fontes: [sid], start: local(new Date(from)), end: local(end) };
  }

  async function poll() {
    clearTimeout(pollTimer);
    if (!active || paused || busy) return;
    busy = true;
    const t0 = Date.now(), gen = generation, erros = {};
    let novos = 0;
    try {
      for (let i = 0; i < SOURCES.length; i++) {
        const [sid, label] = SOURCES[i];
        if (!active || paused || gen !== generation) break;
        el.status.innerHTML = `<span class="spinner-border spinner-border-sm"></span> Consultando ${esc(label)} (${i + 1}/${SOURCES.length})...`;
        try {
          const d = await FLP.api(`/api/threats/live?first=${first}`, { method: "POST", body: body(sid, new Date()) });
          first = false;
          if (gen !== generation) break;
          queried.add(sid);  // firewall ou ADOM mudou no meio da consulta
          Object.assign(erros, d.erros || {});
          const fresh = d.eventos.filter((e) => !seen.has(e.id));
          fresh.forEach(remember);
          d.eventos.forEach((e) => { const t = parse(e.data_hora); if (t && (!newest[sid] || t > newest[sid])) newest[sid] = t; });
          fresh.sort((a, b) => (a.data_hora < b.data_hora ? -1 : a.data_hora > b.data_hora ? 1 : 0));
          queue.push(...fresh);
          novos += fresh.length;
          if (fresh.length) tick();
        } catch (e) {
          erros[sid] = e.message;
        }
      }
      const errs = Object.keys(erros).length;
      el.status.textContent = `Atualizado às ${new Date().toLocaleTimeString("pt-BR")} em ${((Date.now() - t0) / 1000).toFixed(1)} s · ` +
        `${novos} evento(s) novo(s)` + (errs ? ` · ${errs} fonte(s) com erro` : "");
      el.status.title = errs ? Object.entries(erros).map(([k, v]) => `${k}: ${v}`).join("\n") : "";
      if (errs === SOURCES.length) el.status.textContent = `Erro: ${Object.values(erros)[0]}. Nova tentativa na próxima atualização.`;
      if (!stats.eventos && !queue.length && !novos) showEmpty(true);
    } finally {
      busy = false;
      // firewall ou ADOM mudou no meio: recomeça já; senão, ritmo fixo a partir do início da consulta
      if (active && !paused) pollTimer = setTimeout(poll, gen !== generation ? 0 : Math.max(2000, every() - (Date.now() - t0)));
    }
  }

  function remember(e) {
    seen.add(e.id); seenOrder.push(e.id);
    if (seenOrder.length > SEEN_MAX) seen.delete(seenOrder.shift());
  }

  // ---- reprodução: espalha os eventos novos ao longo do intervalo -------------------------------
  function tick() {
    clearTimeout(playTimer);
    if (!active || paused) return;
    let delay = 600;
    if (queue.length) {
      const batch = Math.max(1, Math.ceil(queue.length / 40));  // fila grande: alguns por vez, sem atrasar demais
      queue.splice(0, batch).forEach(play);
      delay = Math.max(120, Math.min(2500, every() / Math.max(queue.length + 1, 1))) / speed();
    }
    playTimer = setTimeout(tick, delay);
  }

  function play(e) {
    if (el.onlyPass.checked && e.bloqueado) return;
    showEmpty(false);
    count(e);
    feed(e);
    arc(e);
  }

  function count(e) {
    stats.eventos += 1;
    if (e.bloqueado) stats.bloqueados += 1;
    if (e.pais) stats.paises[e.pais] = (stats.paises[e.pais] || 0) + 1;
    const top = Object.entries(stats.paises).sort((a, b) => b[1] - a[1]).slice(0, 5);
    const n = (v) => v.toLocaleString("pt-BR");
    el.stats.innerHTML = `<div><b>${n(stats.eventos)}</b> eventos</div><div><b>${n(stats.bloqueados)}</b> bloqueados</div>
      <div class="${stats.eventos - stats.bloqueados ? "live-pass" : ""}"><b>${n(stats.eventos - stats.bloqueados)}</b> não bloqueados</div>
      ${top.length ? `<div class="live-top">${top.map(([c, v]) => `<span>${esc(c)} <b>${n(v)}</b></span>`).join("")}</div>` : ""}`;
  }

  function feed(e) {
    const [name, color] = sev(e.severidade);
    const hora = String(e.data_hora || "").slice(11, 19);
    const src = e.maquina && !e.entrada ? `${e.maquina} (${e.ip_origem})` : e.ip_origem;
    const dst = e.entrada && e.maquina ? `${e.maquina} (${e.ip_destino})` : e.ip_destino || e.destino;
    const item = document.createElement("div");
    item.className = "live-item";
    item.innerHTML = `<div class="d-flex gap-2"><span class="live-time">${esc(hora)}</span>
        <span class="live-name text-truncate" title="${esc(e.ameaca)}">${esc(e.ameaca)}</span>
        <span class="live-sev ms-auto" style="color:${color}">${esc(name)}</span></div>
      <div class="live-path text-truncate">${esc(src || "-")} <span class="live-arrow">→</span> ${esc(dst || "-")}${e.pais ? ` <span class="live-country">${esc(e.pais)}</span>` : ""}</div>
      <div class="live-meta">${esc(e.tipo)} · ${esc(e.firewall || "-")} · <span class="${e.bloqueado ? "" : "live-pass"}">${e.bloqueado ? "bloqueado" : "não bloqueado"}</span></div>`;
    el.feed.prepend(item);
    while (el.feed.children.length > FEED_MAX) el.feed.lastElementChild.remove();
  }

  function arc(e) {
    const [, color] = sev(e.severidade);
    const f = fwPos(e.firewall), c = centroid[e.mapa];
    if (!c || (Math.abs(c[0] - f[0]) < 3 && Math.abs(c[1] - f[1]) < 3)) { pulse(f, color); return; }  // sem país ou no próprio país
    const [a, b] = e.entrada ? [c, f] : [f, c];
    const dx = b[0] - a[0], dy = b[1] - a[1], dist = Math.hypot(dx, dy);
    const mx = (a[0] + b[0]) / 2, my = (a[1] + b[1]) / 2 - Math.min(140, dist * 0.35);
    const d = `M${a[0].toFixed(1)},${a[1].toFixed(1)} Q${mx.toFixed(1)},${my.toFixed(1)} ${b[0].toFixed(1)},${b[1].toFixed(1)}`;
    const g = document.createElementNS(NS, "g");
    g.setAttribute("class", "live-arc");
    g.innerHTML = `<path d="${d}" pathLength="1" stroke="${color}" style="animation-duration:${ARC_MS / speed()}ms"></path>
      <circle r="2.6" fill="${color}"><animateMotion dur="${ARC_MS / speed()}ms" fill="freeze" path="${d}"></animateMotion></circle>`;
    el.arcs.appendChild(g);
    const land = el.svg.querySelector(`.live-land path[data-n="${CSS.escape(e.mapa)}"]`);
    if (land) land.classList.add("hit");
    setTimeout(() => pulse(b, color), ARC_MS / speed());
    setTimeout(() => g.classList.add("out"), (ARC_MS + FADE_MS) / speed());
    setTimeout(() => g.remove(), (ARC_MS + FADE_MS + 800) / speed());
  }

  function pulse(p, color) {
    const c = document.createElementNS(NS, "circle");
    c.setAttribute("cx", p[0].toFixed(1)); c.setAttribute("cy", p[1].toFixed(1)); c.setAttribute("r", "3");
    c.setAttribute("class", "live-pulse"); c.setAttribute("stroke", color);
    el.arcs.appendChild(c);
    setTimeout(() => c.remove(), 1400);
  }

  function showEmpty(on) {
    let box = el.map.querySelector(".live-empty");
    if (!on) { if (box) box.remove(); return; }
    if (box) return;
    el.map.insertAdjacentHTML("beforeend", `<div class="live-empty">Nenhum evento de ameaça nos últimos ${FIRST_MIN} minutos.
      O mapa continua consultando o FortiAnalyzer a cada ${el.every.value} s.</div>`);
  }

  // ---- controles --------------------------------------------------------------------------------
  function reset() {
    first = true; seen = new Set(); seenOrder = []; queue = []; newest = {}; queried = new Set(); generation += 1;
    stats = { eventos: 0, bloqueados: 0, paises: {} };
    el.feed.innerHTML = ""; el.stats.innerHTML = "";
    if (el.arcs) el.arcs.innerHTML = "";
    if (el.svg) el.svg.querySelectorAll(".hit").forEach((p) => p.classList.remove("hit"));
    showEmpty(false);
  }

  async function start() {
    if (active) return;
    active = true;
    try { await loadWorld(); } catch { el.status.textContent = "Não foi possível carregar o mapa."; active = false; return; }
    if (!picker) { picker = FLP.devicePicker(el.devices, el.adom); await picker.load(); await loadFirewalls(); }
    poll(); tick();
  }

  function stop() {
    active = false;
    clearTimeout(pollTimer); clearTimeout(playTimer);
  }

  function setPaused(v) {
    paused = v;
    el.play.innerHTML = paused ? `<i class="bi bi-play-fill"></i> Continuar` : `<i class="bi bi-pause-fill"></i> Pausar`;
    el.map.classList.toggle("paused", paused);
    if (paused) { clearTimeout(pollTimer); clearTimeout(playTimer); el.status.textContent = "Pausado."; }
    else if (active) { poll(); tick(); }
  }

  function init() {
    const $ = (id) => document.getElementById(id);
    el = { adom: $("adom"), devices: $("liveDevices"), every: $("liveEvery"), speed: $("liveSpeed"), onlyPass: $("liveOnlyPass"),
           play: $("livePlay"), status: $("liveStatus"), map: $("liveMap"), feed: $("liveFeed"), stats: $("liveStats") };
    const tab = $("tabLive");
    tab.addEventListener("shown.bs.tab", start);
    tab.addEventListener("hidden.bs.tab", stop);
    el.play.addEventListener("click", () => setPaused(!paused));
    el.every.addEventListener("change", () => { if (active && !paused) poll(); });
    el.speed.addEventListener("change", () => { if (active && !paused) tick(); });
    // firewall ou ADOM diferente: recomeça do zero (o seletor recarrega a lista sozinho quando o ADOM muda)
    let picked = "";
    el.devices.addEventListener("hidden.bs.dropdown", () => {
      const now = [...el.devices.querySelectorAll("input[name=devices]")].map((i) => i.value).join(",");
      if (now === picked) return;
      picked = now; drawFirewalls();
      if (active) { reset(); poll(); }
    });
    el.adom.addEventListener("change", async () => { reset(); if (picker) await loadFirewalls(); if (active) poll(); });
    // aba do navegador escondida: não consulta à toa
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) stop();
      else if (tab.classList.contains("active")) start();
    });
  }

  return { init, _project: (lat, lon) => (world ? project(lat, lon) : null) };
})();
