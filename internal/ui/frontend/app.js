"use strict";
// VeilNet client UI controller. Talks only to the local JSON API served by
// internal/ui; no third-party code, no network calls off the loopback.

const $ = (id) => document.getElementById(id);

async function api(path, opts) {
  const o = Object.assign({ headers: { "Content-Type": "application/json" } }, opts);
  const r = await fetch(path, o);
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.error || ("HTTP " + r.status));
  return body;
}
window.api = api;

/* ------------------------------ formatting ------------------------------ */

const DASH = "—";

function fmtBytes(n) {
  if (n == null) return DASH;
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return (i === 0 ? v.toFixed(0) : v.toFixed(1)) + " " + u[i];
}

function fmtRate(bytesPerSec) { return fmtBytes(bytesPerSec) + "/s"; }

function fmtElapsed(s) {
  if (s == null || s <= 0) return DASH;
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = Math.floor(s % 60);
  return [h, m, sec].map((v) => String(v).padStart(2, "0")).join(":");
}

function latencyClass(ms) {
  if (ms == null || ms < 0) return "";
  if (ms < 80) return "good";
  if (ms < 200) return "mid";
  return "bad";
}

function loadClass(l) {
  if (l == null) return "";
  if (l < 0.5) return "good";
  if (l < 0.8) return "mid";
  return "bad";
}

/* ------------------------------ navigation ------------------------------ */

const TITLES = {
  onboard: "Get started", home: "Home", locations: "Locations", nodes: "Nodes",
  circuit: "Multihop circuit", payment: "Payment", privacy: "Privacy",
  dero: "DERO control plane", wallet: "Wallet", settings: "Settings", diagnostics: "Diagnostics",
  about: "About",
};

function showScreen(name) {
  document.querySelectorAll("#nav button").forEach((b) => {
    b.classList.toggle("active", b.dataset.screen === name);
  });
  document.querySelectorAll(".screen").forEach((s) => {
    s.classList.toggle("active", s.id === "screen-" + name);
  });
  $("page-title").textContent = TITLES[name] || name;
  $("sidebar").classList.remove("open");
  if (name === "payment") refreshPayment();
  if (name === "privacy") refreshPrivacy();
  if (name === "dero") refreshDero();
  if (name === "settings") refreshSettings();
  if ((name === "wallet" || name === "payment") && typeof refreshWallet === "function") {
    refreshWallet(false);
  }
}
window.showScreen = showScreen;

document.querySelectorAll("#nav button").forEach((btn) => {
  btn.addEventListener("click", () => showScreen(btn.dataset.screen));
});
$("nav-toggle").addEventListener("click", () => $("sidebar").classList.toggle("open"));

/* -------------------------------- toasts -------------------------------- */

function toast(msg, kind) {
  const el = document.createElement("div");
  el.className = "toast" + (kind ? " " + kind : "");
  el.textContent = msg;
  $("toasts").appendChild(el);
  window.setTimeout(() => el.remove(), 4500);
}
window.toast = toast;

/* -------------------------------- modal --------------------------------- */
// In-page confirm. Native window.confirm blocks the whole renderer, so the
// UI never uses it.

function confirmDialog(title, body, okLabel) {
  return new Promise((resolve) => {
    const modal = $("modal");
    $("modal-title").textContent = title;
    $("modal-body").textContent = body;
    $("modal-ok").textContent = okLabel || "Approve";
    modal.classList.remove("hidden");
    $("modal-ok").focus();
    const done = (v) => {
      modal.classList.add("hidden");
      $("modal-ok").removeEventListener("click", onOk);
      $("modal-cancel").removeEventListener("click", onNo);
      document.removeEventListener("keydown", onKey);
      resolve(v);
    };
    const onOk = () => done(true);
    const onNo = () => done(false);
    const onKey = (e) => { if (e.key === "Escape") done(false); };
    $("modal-ok").addEventListener("click", onOk);
    $("modal-cancel").addEventListener("click", onNo);
    document.addEventListener("keydown", onKey);
  });
}
window.confirmDialog = confirmDialog;

/* ------------------------------ state view ------------------------------ */

const RING = 553; // 2*pi*r for r=88
const SPARK_POINTS = 60;
const sparkRx = [];
const sparkTx = [];
let lastSample = null;
let lastEngineState = "DOWN";

function pushSpark(arr, v) {
  arr.push(v);
  while (arr.length > SPARK_POINTS) arr.shift();
}

function drawSpark() {
  const peak = Math.max(1, ...sparkRx, ...sparkTx);
  const plot = (arr, el) => {
    if (!arr.length) { el.setAttribute("points", ""); return; }
    const step = 600 / Math.max(1, SPARK_POINTS - 1);
    const pts = arr.map((v, i) => {
      const x = (i + (SPARK_POINTS - arr.length)) * step;
      const y = 116 - (v / peak) * 108;
      return x.toFixed(1) + "," + y.toFixed(1);
    });
    el.setAttribute("points", pts.join(" "));
  };
  plot(sparkRx, $("spark-line-rx"));
  plot(sparkTx, $("spark-line-tx"));
}

function setDial(cls, label) {
  const dial = $("shield-btn");
  dial.className = "dial " + cls;
  $("dial-label").textContent = label;
  const arc = $("ring-arc");
  const off = cls === "up" ? 0 : cls === "connecting" ? RING * 0.75 : RING;
  arc.style.strokeDashoffset = String(off);
}

async function refreshState() {
  let st;
  try { st = await api("/api/state"); }
  catch (e) { return; }

  const s = st.EngineState;
  lastEngineState = s;
  const up = s === "UP";
  const connecting = s === "CONNECTING";
  const failed = s === "FAILED";
  const cls = up ? "up" : connecting ? "connecting" : failed ? "failed" : "down";

  const pill = $("conn-pill");
  pill.className = "pill " + cls;
  pill.querySelector("span").textContent = up ? "PROTECTED" : s;

  setDial(cls, up ? "ON" : connecting ? "…" : failed ? "FAIL" : "OFF");

  $("status-line").textContent = up
    ? "Protected" + (st.Node ? " via " + st.Node.NodeID : "")
    : connecting ? "Connecting…"
    : failed ? "Connection failed"
    : "Disconnected";
  $("status-sub").textContent = up
    ? "Exit: " + (st.Node ? st.Node.Endpoint : DASH) +
      (st.Node && st.Node.City ? "  ·  " + st.Node.City + ", " + st.Node.Country : "")
    : failed ? "The tunnel did not come up. Open Diagnostics for the cause."
    : "Select a node to establish a private tunnel.";

  $("btn-connect").disabled = up || connecting;
  $("btn-disconnect").disabled = !up && !connecting;

  const el = fmtElapsed(st.ElapsedSecs);
  const rx = fmtBytes(st.RxBytes);
  const tx = fmtBytes(st.TxBytes);
  $("stat-elapsed").textContent = el;
  $("stat-rx").textContent = rx;
  $("stat-tx").textContent = tx;
  $("stat-node").textContent = st.Node ? st.Node.NodeID : DASH;
  $("q-elapsed").textContent = el;
  $("q-rx").textContent = rx;
  $("q-tx").textContent = tx;

  // Throughput: delta between samples, reset whenever the tunnel drops.
  const now = Date.now();
  if (!up) {
    lastSample = null;
    sparkRx.length = 0; sparkTx.length = 0;
    $("spark-rx").textContent = "0 B/s";
    $("spark-tx").textContent = "0 B/s";
  } else if (lastSample) {
    const dt = Math.max(0.25, (now - lastSample.t) / 1000);
    const dRx = Math.max(0, (st.RxBytes - lastSample.rx) / dt);
    const dTx = Math.max(0, (st.TxBytes - lastSample.tx) / dt);
    pushSpark(sparkRx, dRx);
    pushSpark(sparkTx, dTx);
    $("spark-rx").textContent = fmtRate(dRx);
    $("spark-tx").textContent = fmtRate(dTx);
  }
  if (up) lastSample = { t: now, rx: st.RxBytes, tx: st.TxBytes };
  drawSpark();

  $("demo-badge").classList.toggle("hidden", !st.Demo);
  $("pay-dot").classList.toggle("hidden", !(st.Payment && st.Payment.PendingApproval));

  if (typeof renderCircuit === "function") renderCircuit(st);
}

/* -------------------------------- nodes --------------------------------- */

let allNodes = [];
let sortKey = "LatencyMs";
let sortDesc = false;

function sortNodes(list) {
  const dir = sortDesc ? -1 : 1;
  return list.slice().sort((a, b) => {
    let x = a[sortKey], y = b[sortKey];
    if (sortKey === "LatencyMs") { // unknown (-1) always sorts last
      x = x < 0 ? Infinity : x;
      y = y < 0 ? Infinity : y;
    }
    if (typeof x === "string") return dir * String(x).localeCompare(String(y));
    return dir * ((x || 0) - (y || 0));
  });
}

async function connectNode(id, node) {
  if (node && node.PricePerHourDero > 0) {
    const ok = await confirmDialog(
      "Approve payment",
      "Node " + id + " costs " + node.PricePerHourDero + " DERO per hour. " +
      "VeilNet never spends without your explicit approval.",
      "Approve and connect");
    if (!ok) { toast("Not approved. Nothing was spent.", "bad"); return; }
  }
  try {
    await api("/api/connect", { method: "POST", body: JSON.stringify({ node_id: id || "" }) });
    toast("Connecting" + (id ? " via " + id : "") + "…", "ok");
  } catch (e) { showError(e); }
  refreshState();
}

function renderNodes() {
  const q = ($("node-search").value || "").toLowerCase().trim();
  const rows = sortNodes(allNodes).filter((n) =>
    !q || (n.NodeID + " " + n.City + " " + n.Country + " " + n.Region + " " + n.Endpoint)
      .toLowerCase().includes(q));

  const tb = document.querySelector("#nodes-table tbody");
  tb.textContent = "";
  for (const n of rows) {
    const tr = document.createElement("tr");

    const cell = (text, cls) => {
      const td = document.createElement("td");
      if (cls) td.className = cls;
      if (text != null) td.textContent = text;
      return td;
    };

    tr.appendChild(cell(n.NodeID, "mono"));

    const loc = cell(null);
    const cc = document.createElement("span");
    cc.className = "cc";
    cc.textContent = n.Country;
    loc.append(cc, document.createTextNode(n.City));
    tr.appendChild(loc);

    tr.appendChild(cell(n.Endpoint, "mono"));
    tr.appendChild(cell(n.PricePerHourDero + " DERO", "num"));
    tr.appendChild(cell(n.LatencyMs >= 0 ? n.LatencyMs + " ms" : DASH, "num " + latencyClass(n.LatencyMs)));

    const ld = cell(null);
    const meter = document.createElement("div");
    meter.className = "meter " + loadClass(n.Load);
    const bar = document.createElement("i");
    bar.style.width = Math.round(Math.min(1, Math.max(0, n.Load || 0)) * 100) + "%";
    meter.appendChild(bar);
    ld.appendChild(meter);
    tr.appendChild(ld);

    tr.appendChild(cell(n.Trust != null ? n.Trust.toFixed(2) : DASH));

    const stat = cell(null);
    const badge = document.createElement("span");
    badge.className = "badge" + (n.Status === "active" ? " ok" : "");
    const dot = document.createElement("i");
    dot.className = "status-dot" + (n.Status === "active" ? " active" : "");
    badge.append(dot, document.createTextNode(n.Status || "unknown"));
    stat.appendChild(badge);
    tr.appendChild(stat);

    const act = cell(null);
    const btn = document.createElement("button");
    btn.textContent = "Connect";
    btn.addEventListener("click", () => connectNode(n.NodeID, n));
    act.appendChild(btn);
    tr.appendChild(act);

    tb.appendChild(tr);
  }
  $("node-empty").classList.toggle("hidden", rows.length > 0);

  document.querySelectorAll("#nodes-table th[data-sort]").forEach((th) => {
    th.classList.toggle("sorted", th.dataset.sort === sortKey);
    th.classList.toggle("desc", th.dataset.sort === sortKey && sortDesc);
  });
}

function renderLocations() {
  const q = ($("loc-search").value || "").toLowerCase().trim();
  const groups = {};
  for (const n of allNodes) {
    const key = n.Country + "|" + n.City + "|" + n.Region;
    (groups[key] = groups[key] || []).push(n);
  }
  const box = $("locations");
  box.textContent = "";
  let shown = 0;

  for (const [key, list] of Object.entries(groups)) {
    const [country, city, region] = key.split("|");
    if (q && !(country + " " + city + " " + region).toLowerCase().includes(q)) continue;
    shown++;

    const lats = list.map((n) => n.LatencyMs).filter((v) => v >= 0);
    const best = lats.length ? Math.min(...lats) : -1;
    const cheapest = Math.min(...list.map((n) => n.PricePerHourDero));
    const avgLoad = list.reduce((a, n) => a + (n.Load || 0), 0) / list.length;

    const card = document.createElement("div");
    card.className = "card clickable";

    const h = document.createElement("h3");
    const cc = document.createElement("span");
    cc.className = "cc";
    cc.textContent = country;
    h.append(cc, document.createTextNode(city));
    card.appendChild(h);

    const add = (k, v, accent) => {
      const dk = document.createElement("div");
      dk.className = "k";
      dk.textContent = k;
      const dv = document.createElement("div");
      dv.className = "v" + (accent ? " accent" : "");
      dv.textContent = v;
      card.append(dk, dv);
    };
    add("region", region);
    add("nodes", String(list.length));
    add("best latency", best >= 0 ? best + " ms" : DASH, true);
    add("from", cheapest + " DERO/h");

    const lk = document.createElement("div");
    lk.className = "k";
    lk.textContent = "load";
    const meter = document.createElement("div");
    meter.className = "meter " + loadClass(avgLoad);
    const bar = document.createElement("i");
    bar.style.width = Math.round(avgLoad * 100) + "%";
    meter.appendChild(bar);
    card.append(lk, meter);

    const pick = sortNodes(list)[0] || list[0];
    card.addEventListener("click", () => connectNode(pick.NodeID, pick));
    box.appendChild(card);
  }
  $("loc-empty").classList.toggle("hidden", shown > 0);
}

async function refreshNodes() {
  try { allNodes = await api("/api/nodes"); }
  catch (e) { return; }
  renderNodes();
  renderLocations();
}

document.querySelectorAll("#nodes-table th[data-sort]").forEach((th) => {
  th.addEventListener("click", () => {
    const k = th.dataset.sort;
    if (k === sortKey) sortDesc = !sortDesc;
    else { sortKey = k; sortDesc = false; }
    renderNodes();
  });
});
$("node-search").addEventListener("input", renderNodes);
$("loc-search").addEventListener("input", renderLocations);

/* ------------------------------- payment -------------------------------- */

async function refreshPayment() {
  const p = await api("/api/payment").catch(() => null);
  if (!p) return;
  const box = $("payment-info");
  box.textContent = "";
  const items = [
    ["Budget cap", p.MaxPerHourDero + " DERO/h", "hard ceiling per hour", false],
    ["Spent last hour", p.SpentLastHour + " DERO", "actual", false],
    ["Receipts", String(p.Receipts), "signed records", false],
    ["Approval pending", p.PendingApproval ? "YES" : "no", "explicit consent", p.PendingApproval],
  ];
  for (const [title, value, k, warn] of items) {
    const c = document.createElement("div");
    c.className = "card";
    const h = document.createElement("h3");
    h.textContent = title;
    const v = document.createElement("div");
    v.className = "v" + (warn ? " " : " accent");
    if (warn) v.classList.add("warn");
    v.textContent = value;
    const kk = document.createElement("div");
    kk.className = "k";
    kk.textContent = k;
    c.append(h, v, kk);
    box.appendChild(c);
  }
}

/* ------------------------------- privacy -------------------------------- */

async function refreshPrivacy() {
  const d = await api("/api/diagnostics").catch(() => null);
  if (!d) return;
  const el = $("privacy-checks");
  el.textContent = "";
  for (const c of [d.Tunnel, d.Enforcement, d.ExitIP, d.DNSRoute, d.IPv6, d.KillSwitch, d.Node, d.Multihop]) {
    if (!c) continue;
    // While the tunnel is down there is nothing to protect yet, so a
    // non-OK check is "not applicable", not a failure. Only flag CHECK
    // once the engine reports UP.
    const neutral = c.Value === "none" || c.Value === "direct" || lastEngineState !== "UP";
    const div = document.createElement("div");
    div.className = "card";

    const h = document.createElement("h3");
    h.textContent = c.Name;
    const badge = document.createElement("span");
    badge.className = "badge " + (c.OK ? "ok" : neutral ? "" : "bad");
    badge.textContent = c.OK ? "OK" : neutral ? DASH : "CHECK";
    h.appendChild(badge);

    const v = document.createElement("div");
    v.className = "v accent";
    v.textContent = c.Value;
    const k = document.createElement("div");
    k.className = "k";
    k.textContent = c.Detail || "";
    div.append(h, v, k);
    el.appendChild(div);
  }
}

/* --------------------------------- dero --------------------------------- */

async function refreshDero() {
  const cfg = await api("/api/config").catch(() => null);
  if (!cfg) return;
  const box = $("dero-info");
  box.textContent = "";
  const items = [
    ["RPC endpoint", (cfg.Dero && cfg.Dero.RPCEndpoint) || DASH],
    ["Network", (cfg.Dero && cfg.Dero.Network) || DASH],
    ["Wallet", (cfg.Wallet && cfg.Wallet.Address) || "none configured"],
    ["Carries", "control + payments only"],
  ];
  for (const [title, value] of items) {
    const c = document.createElement("div");
    c.className = "card";
    const h = document.createElement("h3");
    h.textContent = title;
    const v = document.createElement("div");
    v.className = "v accent mono";
    v.textContent = value;
    c.append(h, v);
    box.appendChild(c);
  }
}

/* ------------------------------- settings ------------------------------- */

async function refreshSettings() {
  const cfg = await api("/api/config").catch(() => null);
  if (!cfg) return;
  const f = $("settings-form");
  f.killswitch.value = cfg.KillSwitch || "ON_WHILE_CONNECTED";
  f.dns_mode.value = (cfg.DNS && cfg.DNS.Mode) || "VEILNET";
  f.dns_servers.value = ((cfg.DNS && cfg.DNS.Servers) || []).join(", ");
  f.region.value = cfg.Region || "";
  f.auto_connect.checked = !!cfg.AutoConnect;
  f.multihop.checked = !!(cfg.Multihop && cfg.Multihop.Enabled);
  f.ipv6.checked = !!(cfg.DNS && cfg.DNS.IPv6Upstream);
  f.cover_mode.value = (cfg.Cover && cfg.Cover.Mode) || "OFF";
  const pol = (cfg.Network && cfg.Network.SelectPolicy) || "FASTEST";
  $("policy").value = pol;
  $("wiz-policy").value = pol;
}

$("settings-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  const cur = await api("/api/config").catch(() => ({}));
  const body = Object.assign({}, cur, {
    KillSwitch: f.killswitch.value,
    Region: f.region.value,
    AutoConnect: f.auto_connect.checked,
    DNS: {
      Mode: f.dns_mode.value,
      Servers: f.dns_servers.value.split(",").map((s) => s.trim()).filter(Boolean),
      IPv6Upstream: f.ipv6.checked,
      DoHURL: (cur.DNS && cur.DNS.DoHURL) || "",
    },
    Multihop: Object.assign({}, cur.Multihop, { Enabled: f.multihop.checked }),
    Cover: Object.assign({}, cur.Cover, { Mode: f.cover_mode.value }),
  });
  try {
    await api("/api/config", { method: "POST", body: JSON.stringify(body) });
    $("settings-msg").textContent = "Saved. This persists across restart.";
    toast("Settings saved.", "ok");
  } catch (err) {
    $("settings-msg").textContent = "Save failed: " + err.message;
    showError(err);
  }
});

$("policy").addEventListener("change", async () => {
  const cur = await api("/api/config").catch(() => ({}));
  const body = Object.assign({}, cur, {
    Network: Object.assign({}, cur.Network, { SelectPolicy: $("policy").value }),
  });
  try {
    await api("/api/config", { method: "POST", body: JSON.stringify(body) });
    toast("Selection policy: " + $("policy").value, "ok");
  } catch (e) { showError(e); }
});

/* -------------------------------- actions ------------------------------- */

function wire(id, fn) {
  const el = $(id);
  if (el) el.addEventListener("click", fn);
}

wire("btn-connect", () => connectNode("", null));
wire("shield-btn", async () => {
  const st = await api("/api/state").catch(() => null);
  if (st && st.EngineState === "UP") $("btn-disconnect").click();
  else connectNode("", null);
});
wire("btn-disconnect", async () => {
  try { await api("/api/disconnect", { method: "POST" }); toast("Disconnected.", "ok"); }
  catch (e) { showError(e); }
  refreshState();
});
wire("btn-autoselect", () => connectNode("", null));
wire("btn-autocircuit", async () => {
  try { await api("/api/circuit", { method: "POST", body: JSON.stringify({ auto: true }) }); toast("2-hop circuit built.", "ok"); }
  catch (e) { showError(e); }
  refreshState();
});
wire("btn-autocircuit3", async () => {
  try { await api("/api/circuit", { method: "POST", body: JSON.stringify({ auto: true, hops: 3 }) }); toast("3-hop circuit built.", "ok"); }
  catch (e) { showError(e); }
  refreshState();
});
wire("btn-rotate", async () => {
  try { await api("/api/rotate", { method: "POST" }); toast("Exit rotated.", "ok"); }
  catch (e) { showError(e); }
  refreshState();
});
wire("btn-guard-reset", async () => {
  const ok = await confirmDialog("Reset entry guard",
    "The pinned entry node will be dropped. The next rebuild picks a fresh entry, which briefly widens your exposure.",
    "Reset guard");
  if (!ok) return;
  try { await api("/api/guard", { method: "POST" }); toast("Guard reset.", "ok"); }
  catch (e) { showError(e); }
  refreshState();
});
wire("btn-approve", async () => {
  try { await api("/api/approve-payment", { method: "POST" }); toast("Approval requested.", "ok"); }
  catch (e) { showError(e); }
  refreshPayment();
});
wire("btn-diag", async () => {
  const d = await api("/api/diagnostics").catch((e) => ({ error: e.message }));
  $("diag-out").textContent = JSON.stringify(d, null, 2);
});
wire("btn-diag-copy", async () => {
  try {
    await navigator.clipboard.writeText($("diag-out").textContent);
    toast("Diagnostics copied.", "ok");
  } catch (e) { toast("Copy blocked by the browser.", "bad"); }
});

/* --------------------------------- init --------------------------------- */

(async function init() {
  await refreshState();
  await refreshNodes();
  await refreshSettings();
  await refreshPayment();
  await refreshPrivacy();
  await refreshDero();
  window.setInterval(refreshState, 1000);
  window.setInterval(refreshNodes, 15000);
  window.setInterval(() => {
    if ($("screen-privacy").classList.contains("active")) refreshPrivacy();
  }, 5000);
})();
