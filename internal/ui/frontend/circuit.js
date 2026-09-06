"use strict";

// Circuit screen: hop chain with countries and per-hop price, guard status,
// rotate + guard-reset actions. Rendered straight from /api/state (Circuit
// snapshot), so no extra round-trip is needed.

function hopRole(i, n) {
  if (n <= 1) return "single hop";
  if (i === 0) return "entry · guard";
  if (i === n - 1) return "exit";
  return "middle";
}

function makeHop(id, country, price, role, cls) {
  const hop = document.createElement("div");
  hop.className = "hop" + (cls ? " " + cls : "");

  const r = document.createElement("div");
  r.className = "hop-role";
  r.textContent = role;

  const h = document.createElement("div");
  h.className = "hop-id";
  h.textContent = id;

  const kc = document.createElement("div");
  kc.className = "k";
  kc.textContent = "country";
  const vc = document.createElement("div");
  vc.className = "v";
  vc.textContent = country || "—";

  const kp = document.createElement("div");
  kp.className = "k";
  kp.textContent = "price";
  const vp = document.createElement("div");
  vp.className = "v";
  vp.textContent = price != null ? price + " DERO/h" : "—";

  hop.append(r, h, kc, vc, kp, vp);
  return hop;
}

function arrow() {
  const a = document.createElement("div");
  a.className = "hop-arrow";
  a.textContent = "→";
  return a;
}

function renderCircuit(st) {
  const chain = document.getElementById("circuit-chain");
  const guard = document.getElementById("circuit-guard");
  const state = document.getElementById("circuit-state");
  if (!chain || !st) return;

  const c = st.Circuit;
  chain.textContent = "";

  if (!c || !c.Active || !c.Hops || c.Hops.length === 0) {
    if (state) state.textContent = "Direct connection (single hop).";
    if (guard) guard.textContent = "Guard: none (build a circuit to pin an entry).";
    return;
  }

  const you = document.createElement("div");
  you.className = "you";
  you.textContent = "Your device";
  chain.append(you, arrow());

  const n = c.Hops.length;
  for (let i = 0; i < n; i++) {
    const cls = i === 0 ? "guard" : i === n - 1 ? "exit" : "";
    chain.appendChild(makeHop(
      c.Hops[i],
      (c.Countries && c.Countries[i]) || "",
      (c.Prices && c.Prices[i] != null) ? c.Prices[i] : null,
      hopRole(i, n),
      cls));
    if (i < n - 1) chain.appendChild(arrow());
  }

  chain.append(arrow());
  const net = document.createElement("div");
  net.className = "you";
  net.textContent = "Internet";
  chain.appendChild(net);

  const label = n === 1 ? "Single hop (fallback — one node sees both ends)"
    : n === 2 ? "2-hop circuit"
    : n + "-hop circuit";
  if (state) state.textContent = label + " · rotations: " + (c.Rotations || 0);

  if (guard) {
    guard.textContent = c.GuardPinned
      ? "Guard pinned: " + (c.Hops[0] || "") + " — rotations keep this entry."
      : "Guard not pinned — the next rebuild pins the entry.";
  }
}
