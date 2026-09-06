"use strict";
// First-run wizard (welcome -> how it works -> speed/region -> connect ->
// done) plus the user-facing error catalog. Catalog codes mirror the
// internal/app classification (service-down, no-nodes, auth-rejected,
// payment-declined, tunnel-failed, dns-blocked); every message carries the
// cause and the concrete fix, never a bare failure.

// Substring match -> [code, fix]. First match wins; unknown errors fall
// through to the generic diagnostics fix.
const ONBOARD_ERRORS = [
  { match: ["service unreachable", "no tunnel engine", "service not", "\\pipe", "connection refused", "failed to fetch"],
    code: "service-down",
    fix: "Start the privileged service, then retry. The GUI never needs admin; the service owns the tunnel." },
  { match: ["no suitable nodes", "no demo nodes", "not found", "no nodes"],
    code: "no-nodes",
    fix: "No usable exits answered. Try Demo mode, pick another region, or check the registry/devnet is up." },
  { match: ["denied request", "wallet denied", "refused the application", "wallet refused"],
    code: "wallet-denied",
    fix: "Your wallet said no, so nothing was spent. Approve VeilNet in the wallet window, then try again." },
  { match: ["xswd", "wallet", "rpc-login"],
    code: "wallet-unreachable",
    fix: "Open your DERO wallet. For XSWD turn the bridge on; for RPC start the wallet RPC server and check the endpoint and login." },
  { match: ["auth", "token", "unauthorized", "rejected", "forbidden", "revoked"],
    code: "auth-rejected",
    fix: "The node rejected authorization. Disconnect, restart the service to refresh credentials, then reconnect." },
  { match: ["payment", "approv", "declin", "insufficient", "spend", "balance"],
    code: "payment-declined",
    fix: "Nothing was spent. Open the Payment screen, review the amount, and approve explicitly." },
  { match: ["dns"],
    code: "dns-blocked",
    fix: "Name resolution is blocked. Set DNS mode to VeilNet in Settings and re-check Diagnostics." },
  { match: ["tunnel", "wireguard", "handshake", "peer", "endpoint", "timeout", "network", "unreachable"],
    code: "tunnel-failed",
    fix: "The encrypted tunnel failed. Retry, auto-select the fastest node, or allow UDP through your firewall." },
];

function onboardLookup(raw) {
  const msg = String((raw && raw.message) || raw || "");
  const low = msg.toLowerCase();
  for (const e of ONBOARD_ERRORS) {
    if (e.match.some((m) => low.includes(m))) return { code: e.code, fix: e.fix, raw: msg };
  }
  return { code: "connect-failed", fix: "Open Diagnostics, then run veilnet --setup for a fix hint.", raw: msg };
}

// showError renders cause + fix in the banner (and falls back to a toast
// only when the banner is absent). All UI connect flows route through here.
function showError(err) {
  const info = onboardLookup(err);
  const banner = document.getElementById("err-banner");
  if (!banner) {
    if (typeof toast === "function") toast(info.raw + " — " + info.fix, "bad");
    return;
  }
  banner.textContent = "";

  const code = document.createElement("b");
  code.textContent = "[" + info.code + "] ";
  const cause = document.createElement("span");
  cause.textContent = info.raw || "request failed";
  const fix = document.createElement("div");
  fix.className = "muted small";
  fix.textContent = "Fix: " + info.fix;

  banner.append(code, cause, fix);
  banner.classList.remove("hidden");
  window.clearTimeout(banner._hide);
  banner._hide = window.setTimeout(() => banner.classList.add("hidden"), 15000);
}
window.showError = showError;

function onboardRail(step) {
  document.querySelectorAll("#wiz-rail li").forEach((li) => {
    const n = Number(li.dataset.step);
    li.classList.toggle("on", n === step);
    li.classList.toggle("done", n < step);
  });
}

function onboardShow(id) {
  if (typeof showScreen === "function") showScreen("onboard");
  document.querySelectorAll(".wiz-step").forEach((s) => s.classList.remove("active"));
  const el = document.getElementById(id);
  if (el) el.classList.add("active");
  onboardRail(Number(String(id).replace("wst-", "")) || 1);
}

function onboardGoHome() {
  try { window.localStorage.setItem("veilnet.onboarded", "1"); } catch (_) { /* private mode */ }
  if (typeof showScreen === "function") showScreen("home");
}

async function onboardSaveSpeedRegion() {
  const policy = document.getElementById("wiz-policy").value;
  const region = document.getElementById("wiz-region").value.trim();
  const cur = await api("/api/config").catch(() => ({}));
  const body = Object.assign({}, cur, {
    Region: region,
    Network: Object.assign({}, cur.Network, { SelectPolicy: policy }),
  });
  await api("/api/config", { method: "POST", body: JSON.stringify(body) });
}

// Fastest-first pick over known latencies; unknown (-1) sorts last.
function pickFastest(nodes) {
  const known = nodes.filter((n) => (n.Status || "active") === "active");
  const pool = known.length ? known : nodes;
  return pool.slice().sort((a, b) => {
    const la = a.LatencyMs < 0 ? 1e12 : a.LatencyMs;
    const lb = b.LatencyMs < 0 ? 1e12 : b.LatencyMs;
    return la - lb;
  })[0];
}

async function onboardConnect() {
  const msg = document.getElementById("wiz-msg");
  msg.textContent = "Finding the fastest node…";
  let nodes;
  try {
    nodes = await api("/api/nodes");
  } catch (e) {
    showError(e);
    msg.textContent = "";
    return;
  }
  if (!nodes || !nodes.length) {
    showError(new Error("no suitable nodes available"));
    msg.textContent = "";
    return;
  }
  const node = pickFastest(nodes);
  // Paid nodes trigger the explicit approval dialog; unpaid dev nodes and
  // demo connect straight through. Nothing is ever spent silently.
  if (node.PricePerHourDero > 0) {
    const ok = await confirmDialog(
      "Approve payment",
      "Node " + node.NodeID + " costs " + node.PricePerHourDero +
      " DERO per hour. Approve explicitly to continue; VeilNet never spends without approval.",
      "Approve and connect");
    if (!ok) {
      msg.textContent = "Not approved — nothing was spent. Pick another node any time.";
      return;
    }
  }
  msg.textContent = "Connecting via " + node.NodeID + "…";
  try {
    await api("/api/connect", { method: "POST", body: JSON.stringify({ node_id: node.NodeID }) });
  } catch (e) {
    showError(e);
    msg.textContent = "";
    return;
  }
  document.getElementById("wiz-done-node").textContent = node.NodeID;
  onboardShow("wst-5");
}

function onboardWire() {
  const go = (from, to) => {
    const el = document.getElementById(from);
    if (el) el.addEventListener("click", () => onboardShow(to));
  };
  go("wiz-next-1", "wst-2");
  go("wiz-back-2", "wst-1");
  go("wiz-next-2", "wst-3");
  go("wiz-back-3", "wst-2");
  go("wiz-back-4", "wst-3");

  const save = document.getElementById("wiz-next-3");
  if (save) save.addEventListener("click", async () => {
    try {
      await onboardSaveSpeedRegion();
      onboardShow("wst-4");
    } catch (e) { showError(e); }
  });

  const connect = document.getElementById("wiz-connect");
  if (connect) connect.addEventListener("click", onboardConnect);
  const done = document.getElementById("wiz-done");
  if (done) done.addEventListener("click", onboardGoHome);
  const skip = document.getElementById("wiz-skip");
  if (skip) skip.addEventListener("click", onboardGoHome);

  // Re-entering the tour from the sidebar always restarts at step 1.
  const nav = document.querySelector('#nav button[data-screen="onboard"]');
  if (nav) nav.addEventListener("click", () => {
    const any = document.querySelector(".wiz-step.active");
    if (!any) onboardShow("wst-1");
  });
}

(function onboardInit() {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", onboardBoot);
  } else {
    onboardBoot();
  }
  function onboardBoot() {
    if (!document.getElementById("screen-onboard")) return;
    onboardWire();
    let seen = null;
    try { seen = window.localStorage.getItem("veilnet.onboarded"); } catch (_) { /* private mode */ }
    if (seen !== "1") onboardShow("wst-1");
  }
})();
