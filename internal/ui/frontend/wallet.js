"use strict";

// Wallet screen: connect the user's DERO wallet over XSWD (the wallet
// approves in its own window) or over wallet JSON-RPC, then show
// address and balance. Connecting is read-only; sending needs a pending
// approval and one more confirmation here.

let walletState = { Mode: "NONE", Connected: false };
let walletMode = "XSWD";

function walletSetMode(mode) {
  walletMode = mode;
  document.querySelectorAll(".seg-btn[data-wmode]").forEach((b) => {
    b.classList.toggle("active", b.dataset.wmode === mode);
  });
  ["XSWD", "RPC", "NONE"].forEach((m) => {
    const el = $("wmode-" + m);
    if (el) el.classList.toggle("hidden", m !== mode);
  });
  const connect = $("btn-wallet-connect");
  if (connect) {
    connect.querySelector("span").textContent =
      mode === "NONE" ? "Run without a wallet" : "Connect wallet";
  }
}

function renderWallet(st) {
  walletState = st || { Mode: "NONE", Connected: false };
  const connected = !!walletState.Connected;

  const pill = $("wallet-pill");
  pill.className = "badge " + (connected ? "ok" : walletState.Error ? "bad" : "");
  pill.textContent = connected ? walletState.Mode + " connected" : "not connected";

  const payPill = $("pay-wallet-pill");
  payPill.className = "badge " + (connected ? "ok" : "");
  payPill.textContent = connected ? walletState.Mode + " wallet ready" : "no wallet";

  $("wallet-dot").classList.toggle("hidden", !connected);
  $("btn-wallet-disconnect").disabled = !connected;
  $("btn-wallet-refresh").disabled = !connected;
  $("btn-pay").disabled = !connected;

  $("wallet-msg").textContent = walletState.Error || "";
  $("wallet-msg").className = "small " + (walletState.Error ? "bad" : "muted");

  const box = $("wallet-info");
  box.textContent = "";
  if (!connected) return;

  const items = [
    ["Mode", walletState.Mode, walletState.Mode === "XSWD"
      ? "the wallet approves every request"
      : "local wallet JSON-RPC"],
    ["Endpoint", walletState.Endpoint || DASH, "loopback only"],
    ["Address", walletState.Address || DASH, "your receiving address"],
    ["Balance", fmtDero(walletState.BalanceDero), "total"],
    ["Spendable", fmtDero(walletState.UnlockedDero), "unlocked"],
    ["Network", walletState.Network || DASH, "control plane"],
  ];
  for (const [title, value, k] of items) {
    const c = document.createElement("div");
    c.className = "card";
    const h = document.createElement("h3");
    h.textContent = title;
    const v = document.createElement("div");
    v.className = "v accent mono wrap";
    v.textContent = value;
    const kk = document.createElement("div");
    kk.className = "k";
    kk.textContent = k;
    c.append(h, v, kk);
    box.appendChild(c);
  }
}

function fmtDero(v) {
  if (v == null) return DASH;
  return Number(v).toFixed(5) + " DERO";
}

async function refreshWallet(force) {
  const st = await api("/api/wallet" + (force ? "?refresh=1" : "")).catch(() => null);
  if (!st) {
    // A view-only client answers 501; hide the screen's live bits
    // rather than showing a scary error.
    renderWallet({ Mode: "NONE", Connected: false });
    return;
  }
  renderWallet(st);
  if (!$("w-rpc-endpoint").value) $("w-rpc-endpoint").value = st.Mode === "RPC" ? (st.Endpoint || "") : "";
}

async function walletPrefill() {
  const cfg = await api("/api/config").catch(() => null);
  if (!cfg || !cfg.Wallet) return;
  $("w-rpc-endpoint").value = cfg.Wallet.Endpoint || "";
  $("w-rpc-user").value = cfg.Wallet.User || "";
  $("w-xswd-endpoint").value = cfg.Wallet.XSWDEndpoint || "ws://127.0.0.1:44326/xswd";
  $("w-appname").value = cfg.Wallet.AppName || "VeilNet";
  if (cfg.Wallet.Mode && cfg.Wallet.Mode !== "NONE") walletSetMode(cfg.Wallet.Mode);
}

async function walletConnect() {
  const btn = $("btn-wallet-connect");
  const msg = $("wallet-msg");
  const spec = { mode: walletMode, persist: $("w-persist").checked };
  if (walletMode === "RPC") {
    spec.endpoint = $("w-rpc-endpoint").value.trim();
    spec.user = $("w-rpc-user").value.trim();
    spec.password = $("w-rpc-pass").value;
  } else if (walletMode === "XSWD") {
    spec.endpoint = $("w-xswd-endpoint").value.trim();
    spec.app_name = $("w-appname").value.trim();
  }

  btn.disabled = true;
  msg.className = "small muted";
  msg.textContent = walletMode === "XSWD"
    ? "Waiting for you to approve VeilNet in your wallet…"
    : "Connecting…";
  try {
    const st = await api("/api/wallet", { method: "POST", body: JSON.stringify(spec) });
    renderWallet(st);
    $("w-rpc-pass").value = "";
    toast(walletMode === "NONE" ? "Running without a wallet." : "Wallet connected.", "ok");
  } catch (e) {
    msg.className = "small bad";
    msg.textContent = e.message;
    showError(e);
  } finally {
    btn.disabled = false;
  }
}

async function walletDisconnect() {
  try {
    const st = await api("/api/wallet/disconnect", { method: "POST" });
    renderWallet(st);
    toast("Wallet disconnected. Saved settings are kept.", "ok");
  } catch (e) { showError(e); }
}

async function walletPay() {
  const dest = $("pay-dest").value.trim();
  const amount = parseFloat($("pay-amount").value);
  const msg = $("pay-msg");
  if (!dest) { msg.className = "small bad"; msg.textContent = "Enter a destination address."; return; }
  if (!(amount > 0)) { msg.className = "small bad"; msg.textContent = "Enter an amount greater than zero."; return; }

  const ok = await confirmDialog(
    "Send payment",
    "Send " + amount + " DERO to " + dest + "? " +
    (walletState.Mode === "XSWD"
      ? "Your wallet will ask you to confirm as well."
      : "This submits the transfer immediately."),
    "Send " + amount + " DERO");
  if (!ok) { msg.className = "small muted"; msg.textContent = "Cancelled. Nothing was spent."; return; }

  msg.className = "small muted";
  msg.textContent = "Waiting for the wallet…";
  try {
    const res = await api("/api/wallet/pay", {
      method: "POST",
      body: JSON.stringify({ destination: dest, amount_dero: amount }),
    });
    msg.className = "small ok";
    msg.textContent = "Sent. txid " + (res.txid || "(pending)");
    toast("Payment sent.", "ok");
    refreshPayment();
    refreshWallet(false);
  } catch (e) {
    msg.className = "small bad";
    msg.textContent = e.message;
    showError(e);
  }
}

(function walletWire() {
  document.querySelectorAll(".seg-btn[data-wmode]").forEach((b) => {
    b.addEventListener("click", () => walletSetMode(b.dataset.wmode));
  });
  $("btn-wallet-connect").addEventListener("click", walletConnect);
  $("btn-wallet-disconnect").addEventListener("click", walletDisconnect);
  $("btn-wallet-refresh").addEventListener("click", () => refreshWallet(true));
  $("btn-pay").addEventListener("click", walletPay);
  walletSetMode("XSWD");
  walletPrefill();
  refreshWallet(false);
})();
