package nodes

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"
)

// Server is the node control API. It binds 127.0.0.1 by default and
// requires the mgmt bearer token on every route.
type Server struct {
	ctrl  *Controller
	token string
	srv   *http.Server
}

// NewServer builds the control API over an existing controller.
func NewServer(ctrl *Controller, bearerToken string) *Server {
	s := &Server{ctrl: ctrl, token: bearerToken}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/capacity", s.handleCapacity)
	mux.HandleFunc("/stats", s.handleStats)
	mux.HandleFunc("/session/authorize", s.handleAuthorize)
	mux.HandleFunc("/session/revoke", s.handleRevoke)
	s.srv = &http.Server{
		Handler:      s.authLoopback(mux),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	return s
}

// Serve binds addr (must be loopback unless allowRemote) and serves.
func (s *Server) Serve(addr string, allowRemote bool) error {
	if !allowRemote && !isLoopbackBind(addr) {
		return errors.New("nodes: refusing non-loopback mgmt bind without allow_remote=true")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.srv.Serve(ln)
}

// ServeListener serves on an existing listener (tests).
func (s *Server) ServeListener(ln net.Listener) error { return s.srv.Serve(ln) }

// Close stops the server.
func (s *Server) Close() error { return s.srv.Close() }

func (s *Server) authLoopback(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Per-IP management-API bucket (HardenAgent hook): floods get
		// 429 before any auth work. Nil guard allows.
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			if !s.ctrl.AllowMgmtRequest(host) {
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}
		}
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			ip := net.ParseIP(host)
			if ip == nil || !ip.IsLoopback() {
				// AllowRemote is enforced at bind time; double-check here
				// by refusing anything that is not loopback when the
				// server token gate cannot prove remote allowance.
				if !s.ctrl.cfg.AllowRemote {
					http.Error(w, "forbidden: non-loopback", http.StatusForbidden)
					return
				}
			}
		}
		if !CheckBearer(s.token, bearerTokenOf(r)) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bearerTokenOf(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	st := s.ctrl.Stats()
	writeJSON(w, map[string]any{
		"status": "online", "node_id": s.ctrl.cfg.NodeID,
		"node_type": st.NodeType, "region": st.Region,
		"version": Version, "protocol_version": ProtocolVersion,
		"uptime_sec": st.UptimeSec, "clients": st.Clients,
		"max_clients": st.MaxClients, "accept_new": s.ctrl.cfg.AcceptNew,
	})
}

func (s *Server) handleCapacity(w http.ResponseWriter, _ *http.Request) {
	active, max, accept := s.ctrl.Capacity()
	writeJSON(w, map[string]any{
		"clients": active, "max_clients": max, "accept_new": accept,
	})
}

func (s *Server) handleStats(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.ctrl.Stats())
}

type authorizeRequest struct {
	Token       string `json:"token"`
	ClientKey   string `json:"client_pubkey"`
	ClientPub   string `json:"client_pub"`
	Endpoint    string `json:"endpoint"`
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req authorizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	pubkey := req.ClientKey
	if pubkey == "" {
		pubkey = req.ClientPub
	}
	ses, err := s.ctrl.Authorize(req.Token, pubkey, req.Endpoint)
	if err != nil {
	switch {
		case errors.Is(err, ErrCapacity), errors.Is(err, ErrBlocked), errors.Is(err, ErrRateLimited):
			http.Error(w, err.Error(), http.StatusTooManyRequests)
		case errors.Is(err, ErrDisabled):
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
		case errors.Is(err, ErrNotAccepting):
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
		default:
			if isAuthFailure(err) {
				http.Error(w, err.Error(), http.StatusUnauthorized)
			} else {
				http.Error(w, err.Error(), http.StatusBadRequest)
			}
		}
		return
	}
	writeJSON(w, map[string]any{
		"token_id": ses.TokenID, "assigned_ip": ses.AssignedIP,
		"expires_at": ses.ExpiresAt.UTC().Format(time.RFC3339),
		"scope":      ses.Scope,
	})
}

type revokeRequest struct {
	TokenID string `json:"token_id"`
	Token   string `json:"token"`
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req revokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id := req.TokenID
	if id == "" {
		id = req.Token
	}
	if id == "" {
		http.Error(w, "token_id required", http.StatusBadRequest)
		return
	}
	if err := s.ctrl.Revoke(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]any{"revoked": id})
}

func isAuthFailure(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "expired") ||
		strings.Contains(msg, "invalid token") ||
		strings.Contains(msg, "revoked") ||
		strings.Contains(msg, "no token validator")
}
