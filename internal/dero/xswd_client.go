// XSWD websocket connector: the production implementation of
// XSWDConnector.
//
// XSWD (DERO wallet-to-dApp protocol) keeps signing inside the user's
// wallet. VeilNet opens the socket, presents an ApplicationData
// handshake, and the WALLET renders the approval prompt for the
// application and for every method it later calls. VeilNet never sees a
// seed, a key or a password: only txids and balances cross the socket.
//
// Nothing here auto-spends. RequestTransfer only asks; a refusal comes
// back as ErrDenied and the caller must surface it unchanged.
package dero

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/websocket"
)

// xswdHandshakeTimeout bounds the wait for the user to accept the app
// in their wallet. It is deliberately generous: a human has to click.
const xswdHandshakeTimeout = 120 * time.Second

// xswdCallTimeout bounds one method call, which may also need a click.
const xswdCallTimeout = 120 * time.Second

// applicationData is the XSWD handshake frame. The wallet shows Name,
// Description and URL to the user before accepting the session.
type applicationData struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	URL         string `json:"url,omitempty"`
}

// xswdReply covers both shapes a wallet may answer with: the
// handshake/permission verdict and a JSON-RPC result.
type xswdReply struct {
	Accepted *bool           `json:"accepted"`
	Message  string          `json:"message"`
	ID       *int            `json:"id"`
	Result   json.RawMessage `json:"result"`
	Error    *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// XSWDClient implements XSWDConnector over the wallet's XSWD socket.
type XSWDClient struct {
	mu   sync.Mutex
	conn *websocket.Conn
	cfg  XSWDConfig
	seq  int
}

// NewXSWDClient returns a disconnected XSWD bridge client.
func NewXSWDClient() *XSWDClient { return &XSWDClient{} }

// NewXSWDConfig fills in the documented defaults and derives a stable
// 64-hex application id from appName so the wallet can remember the
// user's earlier decision instead of re-prompting on every launch.
func NewXSWDConfig(endpoint, appName string) XSWDConfig {
	if endpoint == "" {
		endpoint = "ws://127.0.0.1:44326/xswd"
	}
	if appName == "" {
		appName = "VeilNet"
	}
	return XSWDConfig{AppID: appIDFor(appName), AppName: appName, Endpoint: endpoint}
}

// appIDFor derives the 64-hex application id XSWD expects.
func appIDFor(appName string) string {
	sum := sha256.Sum256([]byte("veilnet-xswd:" + appName))
	return hex.EncodeToString(sum[:])
}

// Connect opens the socket and performs the ApplicationData handshake.
// It blocks until the user accepts or refuses in their wallet.
func (c *XSWDClient) Connect(ctx context.Context, cfg XSWDConfig) error {
	if cfg.Endpoint == "" {
		return errors.New("dero: XSWD endpoint required")
	}
	if cfg.AppID == "" {
		cfg.AppID = appIDFor(cfg.AppName)
	}
	if len(cfg.AppID) != 64 {
		return errors.New("dero: XSWD AppID must be 64 hex characters")
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil {
		return fmt.Errorf("%w: bad XSWD endpoint: %v", ErrDeroUnavailable, err)
	}
	if u.Scheme != "ws" && u.Scheme != "wss" {
		return fmt.Errorf("%w: XSWD endpoint must be ws:// or wss://", ErrDeroUnavailable)
	}
	origin := "http://" + u.Host

	wsCfg, err := websocket.NewConfig(cfg.Endpoint, origin)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDeroUnavailable, err)
	}
	conn, err := websocket.DialConfig(wsCfg)
	if err != nil {
		return fmt.Errorf("%w: XSWD dial failed (is the wallet running with XSWD enabled?): %v",
			ErrDeroUnavailable, err)
	}

	c.mu.Lock()
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.conn = conn
	c.cfg = cfg
	c.seq = 0
	c.mu.Unlock()

	app := applicationData{
		ID:          cfg.AppID,
		Name:        cfg.AppName,
		Description: "VeilNet privacy VPN: explicit, user-approved session payments only.",
	}
	if err := c.writeJSON(app, xswdHandshakeTimeout); err != nil {
		c.Close()
		return err
	}
	reply, err := c.readReply(ctx, xswdHandshakeTimeout)
	if err != nil {
		c.Close()
		return err
	}
	if reply.Accepted != nil && !*reply.Accepted {
		c.Close()
		msg := reply.Message
		if msg == "" {
			msg = "wallet refused the application"
		}
		return fmt.Errorf("%w: %s", ErrDenied, msg)
	}
	if reply.Error != nil {
		c.Close()
		return fmt.Errorf("dero: XSWD handshake: %s", reply.Error.Message)
	}
	return nil
}

// Connected reports a live bridge session.
func (c *XSWDClient) Connected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn != nil
}

// Endpoint returns the configured XSWD socket URL.
func (c *XSWDClient) Endpoint() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cfg.Endpoint
}

// Close ends the bridge session. It is safe to call twice.
func (c *XSWDClient) Close() error {
	c.mu.Lock()
	conn := c.conn
	c.conn = nil
	c.mu.Unlock()
	if conn == nil {
		return nil
	}
	return conn.Close()
}

// Call issues one JSON-RPC method over the bridge and decodes the
// result into out. The wallet may prompt the user; a refusal returns
// ErrDenied.
func (c *XSWDClient) Call(ctx context.Context, method string, params any, out any) error {
	c.mu.Lock()
	if c.conn == nil {
		c.mu.Unlock()
		return errors.New("dero: XSWD not connected")
	}
	c.seq++
	id := c.seq
	c.mu.Unlock()

	req := rpcRequest{JSONRPC: "2.0", ID: id, Method: method, Params: params}
	if err := c.writeJSON(req, xswdCallTimeout); err != nil {
		return err
	}
	reply, err := c.readReply(ctx, xswdCallTimeout)
	if err != nil {
		return err
	}
	if reply.Accepted != nil && !*reply.Accepted {
		msg := reply.Message
		if msg == "" {
			msg = "wallet refused " + method
		}
		return fmt.Errorf("%w: %s", ErrDenied, msg)
	}
	if reply.Error != nil {
		if isDenialMessage(reply.Error.Message) {
			return fmt.Errorf("%w: %s", ErrDenied, reply.Error.Message)
		}
		return fmt.Errorf("dero: XSWD %s: %s", method, reply.Error.Message)
	}
	if out != nil && len(reply.Result) > 0 {
		if err := json.Unmarshal(reply.Result, out); err != nil {
			return fmt.Errorf("dero: decode XSWD %s: %w", method, err)
		}
	}
	return nil
}

// GetAddress asks the wallet for its address over the bridge.
func (c *XSWDClient) GetAddress(ctx context.Context) (string, error) {
	var v struct {
		Address string `json:"address"`
	}
	if err := c.Call(ctx, "GetAddress", map[string]any{}, &v); err != nil {
		return "", err
	}
	return v.Address, nil
}

// GetBalance asks the wallet for its balance over the bridge.
func (c *XSWDClient) GetBalance(ctx context.Context) (Balance, error) {
	var v struct {
		Balance         uint64 `json:"balance"`
		UnlockedBalance uint64 `json:"unlocked_balance"`
	}
	if err := c.Call(ctx, "GetBalance", map[string]any{}, &v); err != nil {
		return Balance{}, err
	}
	return Balance{Balance: v.Balance, UnlockedBalance: v.UnlockedBalance}, nil
}

// RequestTransfer asks the wallet to approve and send. The user
// confirms inside the wallet; a refusal returns ErrDenied and an empty
// txid. VeilNet never signs and never retries a denial.
func (c *XSWDClient) RequestTransfer(ctx context.Context, dest string, amountAtomic uint64) (string, error) {
	if dest == "" {
		return "", errors.New("dero: empty destination")
	}
	if amountAtomic == 0 {
		return "", errors.New("dero: zero amount")
	}
	params := map[string]any{
		"destination": dest,
		"amount":      amountAtomic,
		"ringsize":    32,
	}
	var v struct {
		TXID string `json:"txid"`
	}
	if err := c.Call(ctx, "transfer", params, &v); err != nil {
		return "", err
	}
	return v.TXID, nil
}

// ---- framing helpers ----

func (c *XSWDClient) writeJSON(v any, timeout time.Duration) error {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return errors.New("dero: XSWD not connected")
	}
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if err := websocket.JSON.Send(conn, v); err != nil {
		return fmt.Errorf("%w: XSWD write: %v", ErrDeroUnavailable, err)
	}
	return nil
}

// readReply waits for one frame, honouring ctx cancellation.
func (c *XSWDClient) readReply(ctx context.Context, timeout time.Duration) (xswdReply, error) {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return xswdReply{}, errors.New("dero: XSWD not connected")
	}
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetReadDeadline(deadline)

	type result struct {
		reply xswdReply
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		var reply xswdReply
		err := websocket.JSON.Receive(conn, &reply)
		ch <- result{reply, err}
	}()

	select {
	case <-ctx.Done():
		_ = conn.SetReadDeadline(time.Now())
		return xswdReply{}, ctx.Err()
	case r := <-ch:
		if r.err != nil {
			return xswdReply{}, fmt.Errorf("%w: XSWD read: %v", ErrDeroUnavailable, r.err)
		}
		return r.reply, nil
	}
}

// isDenialMessage recognises the wallet's refusal wording so a user
// saying "no" is never reported as a transport failure.
func isDenialMessage(msg string) bool {
	low := strings.ToLower(msg)
	for _, k := range []string{"denied", "rejected", "refused", "not allowed", "permission"} {
		if strings.Contains(low, k) {
			return true
		}
	}
	return false
}
