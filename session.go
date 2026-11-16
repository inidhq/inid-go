package inid

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// ---------- cookies ----------

func parseCookies(r *http.Request) map[string]string {
	jar := map[string]string{}
	for _, header := range r.Header.Values("Cookie") {
		for _, part := range strings.Split(header, ";") {
			part = strings.TrimSpace(part)
			at := strings.Index(part, "=")
			if at <= 0 {
				continue
			}
			value := part[at+1:]
			if decoded, err := url.PathUnescape(value); err == nil {
				value = decoded
			}
			jar[part[:at]] = value
		}
	}
	return jar
}

// encodeURIComponent, as browsers and the other InID SDKs encode cookie values
func encodeURIComponent(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || strings.IndexByte("-_.!~*'()", ch) >= 0 {
			b.WriteByte(ch)
		} else {
			fmt.Fprintf(&b, "%%%02X", ch)
		}
	}
	return b.String()
}

func serializeJar(jar map[string]string) string {
	names := make([]string, 0, len(jar))
	for k := range jar {
		names = append(names, k)
	}
	sort.Strings(names)
	parts := make([]string, len(names))
	for i, k := range names {
		parts[i] = k + "=" + encodeURIComponent(jar[k])
	}
	return strings.Join(parts, "; ")
}

func cookie(name, value string, maxAge int, path string, secure bool) string {
	c := fmt.Sprintf("%s=%s; Path=%s; Max-Age=%d; HttpOnly; SameSite=Lax", name, encodeURIComponent(value), path, maxAge)
	if secure {
		c += "; Secure"
	}
	return c
}

func sessionCookies(t *tokens, secure bool) []string {
	return []string{
		cookie(cookieSession, t.IDToken, cookieMaxAge, "/", secure),
		cookie(cookieRefresh, t.RefreshToken, cookieMaxAge, "/", secure),
	}
}

func clearCookies(secure bool) []string {
	return []string{cookie(cookieSession, "", 0, "/", secure), cookie(cookieRefresh, "", 0, "/", secure)}
}

// ---------- small helpers ----------

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func random(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // the system has no randomness: nothing safe can be done
	}
	return b64url(b)
}

func challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return b64url(sum[:])
}

// ---------- the token endpoint ----------

type tokens struct {
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
}

func (c *Client) basicAuth() string {
	raw := encodeURIComponent(c.cfg.PublishableKey) + ":" + encodeURIComponent(c.cfg.SecretKey)
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(raw))
}

// postForm sends a form to InID with the app's Basic credentials.
func (c *Client) postForm(ctx context.Context, path string, form url.Values) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", c.cfg.Issuer+path, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", c.basicAuth())
	return c.http.Do(req)
}

// token returns *Error with the status InID answered; any other error means it wasn't reached.
func (c *Client) token(ctx context.Context, form url.Values) (*tokens, error) {
	res, err := c.postForm(ctx, "/oauth/token", form)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	var body struct {
		tokens
		Error string `json:"error"`
	}
	_ = json.NewDecoder(res.Body).Decode(&body)
	if res.StatusCode < 200 || res.StatusCode > 299 {
		code := body.Error
		if code == "" {
			code = "token_failed"
		}
		return nil, &Error{Code: code, Status: res.StatusCode}
	}
	return &body.tokens, nil
}

// ---------- reading the session ----------

type sessionResult struct {
	session    *Session
	setCookies []string
	// The request's cookies after a renewal, for the rest of this same request (nil = unchanged)
	cookieHeader *string
}

// readSession is the session in the request's cookies. With renew, one that ends within a
// minute is renewed with the refresh token.
func (c *Client) readSession(r *http.Request, renew, secure bool) (*sessionResult, error) {
	jar := parseCookies(r)
	var current *verified
	if raw := jar[cookieSession]; raw != "" {
		v, err := c.verifyIDToken(raw, "", false)
		if err != nil {
			return nil, err
		}
		current = v
	}
	now := c.now().Unix()
	if current != nil && current.exp-now > renewBefore {
		return &sessionResult{session: sessionOf(current)}, nil
	}
	var stillGood *Session
	if current != nil && !current.expired {
		stillGood = sessionOf(current)
	}
	if !renew || jar[cookieRefresh] == "" {
		return &sessionResult{session: stillGood}, nil
	}
	t, err := c.token(r.Context(), url.Values{"grant_type": {"refresh_token"}, "refresh_token": {jar[cookieRefresh]}})
	var renewed *verified
	if err == nil {
		renewed, err = c.verifyIDToken(t.IDToken, "", false)
		if err == nil && renewed == nil {
			err = &Error{Code: "invalid_id_token", Status: 400}
		}
	}
	if err != nil {
		var ie *Error
		// InID said no (signed out elsewhere, access taken back): the session is over
		if errors.As(err, &ie) && ie.Status >= 400 && ie.Status < 500 && ie.Code != "jwks_unavailable" {
			delete(jar, cookieSession)
			delete(jar, cookieRefresh)
			header := serializeJar(jar)
			return &sessionResult{setCookies: clearCookies(secure), cookieHeader: &header}, nil
		}
		// InID couldn't be reached: what's still valid stays
		return &sessionResult{session: stillGood}, nil
	}
	jar[cookieSession], jar[cookieRefresh] = t.IDToken, t.RefreshToken
	header := serializeJar(jar)
	return &sessionResult{session: sessionOf(renewed), setCookies: sessionCookies(t, secure), cookieHeader: &header}, nil
}

// SessionOf reads who is signed in from a request's cookies, without renewing (the
// middleware is what renews). Nil when nobody is.
func (c *Client) SessionOf(r *http.Request) (*Session, error) {
	res, err := c.readSession(r, false, c.secure(r))
	if err != nil {
		return nil, err
	}
	return res.session, nil
}

// origin is the app's own address: AppURL, else what the request says.
func (c *Client) origin(r *http.Request) string {
	if c.cfg.AppURL != "" {
		return c.cfg.AppURL
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func (c *Client) secure(r *http.Request) bool { return strings.HasPrefix(c.origin(r), "https://") }
