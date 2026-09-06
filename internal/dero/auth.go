// HTTP authentication for wallet/daemon JSON-RPC servers started with
// `--rpc-login user:pass`.
//
// DERO builds have shipped both Basic and Digest challenges on that
// flag, so this file speaks both: the first attempt is unauthenticated,
// and a 401 is answered from the server's own WWW-Authenticate header.
// Credentials never leave the loopback endpoint the user configured and
// are never logged.
package dero

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// creds carries optional rpc-login credentials. A zero value disables
// authentication entirely.
type creds struct {
	user string
	pass string
}

func (c creds) empty() bool { return c.user == "" && c.pass == "" }

// challenge is the parsed WWW-Authenticate header of a 401 response.
type challenge struct {
	scheme string // "basic" or "digest"
	params map[string]string
}

func parseChallenge(header string) challenge {
	ch := challenge{params: map[string]string{}}
	header = strings.TrimSpace(header)
	if header == "" {
		return ch
	}
	sp := strings.IndexByte(header, ' ')
	if sp < 0 {
		ch.scheme = strings.ToLower(header)
		return ch
	}
	ch.scheme = strings.ToLower(header[:sp])
	for _, part := range splitAuthParams(header[sp+1:]) {
		eq := strings.IndexByte(part, '=')
		if eq < 0 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(part[:eq]))
		v := strings.Trim(strings.TrimSpace(part[eq+1:]), `"`)
		ch.params[k] = v
	}
	return ch
}

// splitAuthParams splits on commas that are not inside quotes.
func splitAuthParams(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
			cur.WriteRune(r)
		case r == ',' && !inQuote:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func md5hex(parts ...string) string {
	sum := md5.Sum([]byte(strings.Join(parts, ":")))
	return hex.EncodeToString(sum[:])
}

func clientNonce() string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "00000000feedface"
	}
	return hex.EncodeToString(raw[:])
}

// authorization builds the Authorization header value answering ch for
// one request. It returns "" when the scheme is unsupported.
func (c creds) authorization(ch challenge, method, rawURL string) string {
	switch ch.scheme {
	case "basic":
		return "Basic " + basicToken(c.user, c.pass)
	case "digest":
		return c.digest(ch, method, rawURL)
	default:
		return ""
	}
}

func basicToken(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}

// digest implements RFC 2617 MD5 digest with qop=auth, which is what
// the DERO rpc-server emits.
func (c creds) digest(ch challenge, method, rawURL string) string {
	realm := ch.params["realm"]
	nonce := ch.params["nonce"]
	if nonce == "" {
		return ""
	}
	uri := "/"
	if u, err := url.Parse(rawURL); err == nil && u.Path != "" {
		uri = u.Path
		if u.RawQuery != "" {
			uri += "?" + u.RawQuery
		}
	}
	ha1 := md5hex(c.user, realm, c.pass)
	ha2 := md5hex(method, uri)

	qop := ch.params["qop"]
	if strings.Contains(qop, "auth-int") && !strings.Contains(qop, "auth,") {
		qop = "auth-int"
	} else if strings.Contains(qop, "auth") {
		qop = "auth"
	} else {
		qop = ""
	}

	var response string
	fields := []string{
		fmt.Sprintf(`username=%q`, c.user),
		fmt.Sprintf(`realm=%q`, realm),
		fmt.Sprintf(`nonce=%q`, nonce),
		fmt.Sprintf(`uri=%q`, uri),
	}
	if qop == "auth" {
		cnonce := clientNonce()
		const nc = "00000001"
		response = md5hex(ha1, nonce, nc, cnonce, qop, ha2)
		fields = append(fields,
			"qop=auth",
			"nc="+nc,
			fmt.Sprintf(`cnonce=%q`, cnonce))
	} else {
		response = md5hex(ha1, nonce, ha2)
	}
	fields = append(fields, fmt.Sprintf(`response=%q`, response))
	if op := ch.params["opaque"]; op != "" {
		fields = append(fields, fmt.Sprintf(`opaque=%q`, op))
	}
	if al := ch.params["algorithm"]; al != "" {
		fields = append(fields, "algorithm="+al)
	}
	return "Digest " + strings.Join(fields, ", ")
}

// applyRetryAuth reads the 401 challenge from resp and stamps the
// matching Authorization header onto req. It reports whether the
// request is worth retrying.
func (c creds) applyRetryAuth(req *http.Request, resp *http.Response) bool {
	if c.empty() || resp == nil || resp.StatusCode != http.StatusUnauthorized {
		return false
	}
	ch := parseChallenge(resp.Header.Get("WWW-Authenticate"))
	if ch.scheme == "" {
		ch.scheme = "basic" // server refused without saying how; try Basic
	}
	hdr := c.authorization(ch, req.Method, req.URL.String())
	if hdr == "" {
		return false
	}
	req.Header.Set("Authorization", hdr)
	return true
}
