package ipc

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"sync"
)

// Server hosts engine/firewall/DNS ops behind token auth.
type Server struct {
	token   string
	handler Handler

	mu  sync.Mutex
	lns []net.Listener
	done chan struct{}
}

// NewServer builds a server with the given token and op handler.
func NewServer(token string, h Handler) *Server {
	return &Server{token: token, handler: h, done: make(chan struct{})}
}

// Serve accepts connections on ln until Close.
func (s *Server) Serve(ln net.Listener) {
	s.mu.Lock()
	s.lns = append(s.lns, ln)
	s.mu.Unlock()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				continue
			}
		}
		go s.serveConn(conn)
	}
}

// Close stops all listeners.
func (s *Server) Close() {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ln := range s.lns {
		ln.Close()
	}
	s.lns = nil
}

func (s *Server) serveConn(conn net.Conn) {
	defer conn.Close()
	var req Request
	if err := readFrame(conn, &req); err != nil {
		_ = writeFrame(conn, Response{OK: false, Error: "bad request"})
		return
	}
	if subtle.ConstantTimeCompare([]byte(req.Token), []byte(s.token)) != 1 {
		_ = writeFrame(conn, Response{OK: false, Error: "unauthorized"})
		return
	}
	out, err := s.handler(req.Op, req.Payload)
	if err != nil {
		_ = writeFrame(conn, Response{OK: false, Error: err.Error()})
		return
	}
	var raw json.RawMessage
	if out != nil {
		raw, err = json.Marshal(out)
		if err != nil {
			_ = writeFrame(conn, Response{OK: false, Error: err.Error()})
			return
		}
	}
	_ = writeFrame(conn, Response{OK: true, Payload: raw})
}

// Client dials the service with token auth.
type Client struct {
	token   string
	dial    func() (net.Conn, error)
}

// NewClient builds a dialer for the platform default transport.
func NewClient(token string) *Client {
	return &Client{token: token, dial: defaultDial}
}

// NewTCPClient dials a TCP address (all platforms; tests, non-Windows).
func NewTCPClient(token, addr string) *Client {
	if addr == "" {
		addr = DefaultTCPAddr
	}
	return &Client{token: token, dial: func() (net.Conn, error) {
		return net.Dial("tcp", addr)
	}}
}

// Call invokes op and decodes the payload into out (may be nil).
func (c *Client) Call(op string, payload any, out any) error {
	conn, err := c.dial()
	if err != nil {
		return fmt.Errorf("dial service: %w", err)
	}
	defer conn.Close()
	var raw json.RawMessage
	if payload != nil {
		raw, err = json.Marshal(payload)
		if err != nil {
			return err
		}
	}
	if err := writeFrame(conn, Request{Token: c.token, Op: op, Payload: raw}); err != nil {
		return err
	}
	var resp Response
	if err := readFrame(conn, &resp); err != nil {
		return err
	}
	if !resp.OK {
		if resp.Error == "" {
			resp.Error = "unknown service error"
		}
		return fmt.Errorf("service %s: %s", op, resp.Error)
	}
	if out != nil && len(resp.Payload) > 0 {
		return json.Unmarshal(resp.Payload, out)
	}
	return nil
}
