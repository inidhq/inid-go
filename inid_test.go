package inid

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------- a fake InID ----------

var (
	testKey     *rsa.PrivateKey
	testKeyOnce sync.Once
)

func signingKey(t *testing.T) *rsa.PrivateKey {
	testKeyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		testKey = k
	})
	return testKey
}

type fakeInID struct {
	t   *testing.T
	srv *httptest.Server
	key *rsa.PrivateKey
	kid string

	mu          sync.Mutex
	tokenStatus int    // what /oauth/token answers (0 = 200)
	tokenDown   bool   // /oauth/token drops the connection
	nextNonce   string // the nonce the next ID token carries
	tokenForms  []url.Values
	tokenAuth   []string
	revoked     []url.Values
	revokeAuth  string
	jwksHits    int
	deleted     []string
}

func newFake(t *testing.T) *fakeInID {
	f := &fakeInID{t: t, key: signingKey(t), kid: "k1"}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeInID) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.URL.Path == "/.well-known/jwks.json":
		f.jwksHits++
		pub := f.key.PublicKey
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{
			{"kty": "EC", "kid": "ec1", "crv": "P-256"},
			{"kty": "RSA", "kid": f.kid, "alg": "RS256", "use": "sig",
				"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())},
		}})
	case r.URL.Path == "/oauth/token":
		if f.tokenDown {
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
			return
		}
		_ = r.ParseForm()
		f.tokenForms = append(f.tokenForms, r.PostForm)
		f.tokenAuth = append(f.tokenAuth, r.Header.Get("Authorization"))
		if f.tokenStatus != 0 {
			w.WriteHeader(f.tokenStatus)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		claims := f.claims(600)
		if f.nextNonce != "" {
			claims["nonce"] = f.nextNonce
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id_token": f.sign(claims), "refresh_token": "rt_new", "access_token": "at", "expires_in": 600})
	case r.URL.Path == "/oauth/revoke":
		_ = r.ParseForm()
		f.revoked = append(f.revoked, r.PostForm)
		f.revokeAuth = r.Header.Get("Authorization")
	case r.URL.Path == "/v1/users/u1/sessions" && r.Method == "GET":
		if r.Header.Get("Authorization") != "Bearer sk_test_secret" {
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write([]byte(`{"sessions":[{"id":"s1","createdAt":"a","lastActiveAt":"b","device":"Mac"},{"id":"s2","createdAt":"c","lastActiveAt":"d","device":null},{"id":"s3","createdAt":"e","lastActiveAt":"f","device":null}]}`))
	case strings.HasPrefix(r.URL.Path, "/v1/users/u1/sessions/") && r.Method == "DELETE":
		f.deleted = append(f.deleted, strings.TrimPrefix(r.URL.Path, "/v1/users/u1/sessions/"))
		_, _ = w.Write([]byte(`{"ended":1}`))
	default:
		w.WriteHeader(404)
	}
}

// claims for an ID token InID would sign for this app, ending in `in` seconds
func (f *fakeInID) claims(in int64) map[string]any {
	return map[string]any{
		"iss": f.srv.URL, "aud": "pk_test_app", "sub": "u1", "sid": "s2",
		"exp": time.Now().Unix() + in, "iat": time.Now().Unix(),
		"given_name": "Ana", "family_name": "Gómez", "email": "ana@correo.co", "email_verified": true,
		"phone_number": "+573001234567", "roles": []any{"staff"}, "permissions": []any{"orders:read"},
		"public_metadata": map[string]any{"plan": "pro"},
	}
}

func (f *fakeInID) sign(claims map[string]any) string { return signWith(f.key, f.kid, claims) }

func signWith(key *rsa.PrivateKey, kid string, claims map[string]any) string {
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"})
	c, _ := json.Marshal(claims)
	data := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	digest := sha256.Sum256([]byte(data))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	return data + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func newClient(t *testing.T, f *fakeInID) *Client {
	c, err := New(Config{PublishableKey: "pk_test_app", SecretKey: "sk_test_secret", Issuer: f.srv.URL + "/", AppURL: "https://app.example", WebhookSecret: "whsec_test"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// ---------- helpers ----------

type seen struct {
	auth   *Auth
	cookie string
	called bool
}

func run(c *Client, req *http.Request, opts ...Option) (*httptest.ResponseRecorder, *seen) {
	s := &seen{}
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.called, s.auth, s.cookie = true, FromContext(r.Context()), r.Header.Get("Cookie")
		_, _ = w.Write([]byte("page"))
	})
	rec := httptest.NewRecorder()
	c.Middleware(app, opts...).ServeHTTP(rec, req)
	return rec, s
}

func get(path string, cookies ...string) *http.Request {
	r := httptest.NewRequest("GET", "https://app.example"+path, nil)
	if len(cookies) > 0 {
		r.Header.Set("Cookie", strings.Join(cookies, "; "))
	}
	return r
}

func setCookie(rec *httptest.ResponseRecorder, name string) string {
	for _, c := range rec.Result().Header.Values("Set-Cookie") {
		if strings.HasPrefix(c, name+"=") {
			return c
		}
	}
	return ""
}

func check(t *testing.T, what string, got, want any) {
	t.Helper()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("%s: got %v, want %v", what, got, want)
	}
}

// signIn starts a sign-in and returns its state, flow and flow cookie
func signIn(t *testing.T, c *Client, query string, cookies ...string) (url.Values, flow, string) {
	t.Helper()
	rec, _ := run(c, get("/api/inid/signin?"+query, cookies...))
	if rec.Code != 302 {
		t.Fatalf("signin: status %d", rec.Code)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	q := loc.Query()
	fc := setCookie(rec, "__inid_flow_"+q.Get("state"))
	value := strings.SplitN(strings.SplitN(fc, ";", 2)[0], "=", 2)[1]
	raw, _ := base64.RawURLEncoding.DecodeString(value)
	var fl flow
	if err := json.Unmarshal(raw, &fl); err != nil {
		t.Fatalf("flow cookie: %v", err)
	}
	return q, fl, "__inid_flow_" + fl.State + "=" + value
}

// ---------- 0. configuration ----------

func TestConfig(t *testing.T) {
	if _, err := New(Config{SecretKey: "sk_x"}); err == nil || !strings.Contains(err.Error(), "INID_PUBLISHABLE_KEY") {
		t.Errorf("missing pk: %v", err)
	}
	if _, err := New(Config{PublishableKey: "pk_x", SecretKey: "nope"}); err == nil || !strings.Contains(err.Error(), "INID_SECRET_KEY") {
		t.Errorf("bad sk: %v", err)
	}
	t.Setenv("INID_PUBLISHABLE_KEY", "pk_test_env")
	t.Setenv("INID_SECRET_KEY", "sk_test_env")
	t.Setenv("INID_ISSUER", "")
	c, err := NewFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	cfg := c.Config()
	check(t, "defaults", []string{cfg.PublishableKey, cfg.Issuer, cfg.APIPath, cfg.Scope}, []string{"pk_test_env", "https://id.inid.co", "/api/inid", "openid profile email phone"})
}

// ---------- 1. signin ----------

func TestSignInRedirect(t *testing.T) {
	f := newFake(t)
	c := newClient(t, f)
	rec, _ := run(c, get("/api/inid/signin?return_to=/dashboard%3Ftab%3D1&ui_locales=en&login_hint=ana&entrance=team"))
	check(t, "status", rec.Code, 302)
	check(t, "cache-control", rec.Header().Get("Cache-Control"), "no-store")
	loc, _ := url.Parse(rec.Header().Get("Location"))
	check(t, "authorize", loc.Scheme+"://"+loc.Host+loc.Path, f.srv.URL+"/oauth/authorize")
	q := loc.Query()
	check(t, "client_id", q.Get("client_id"), "pk_test_app")
	check(t, "redirect_uri", q.Get("redirect_uri"), "https://app.example/api/inid/callback")
	check(t, "response_type", q.Get("response_type"), "code")
	check(t, "scope", q.Get("scope"), "openid profile email phone")
	check(t, "method", q.Get("code_challenge_method"), "S256")
	check(t, "passed", []string{q.Get("ui_locales"), q.Get("login_hint"), q.Get("entrance"), q.Get("prompt")}, []string{"en", "ana", "team", ""})
	if len(q.Get("state")) != 22 || len(q.Get("nonce")) != 22 {
		t.Errorf("state/nonce: %q %q", q.Get("state"), q.Get("nonce"))
	}

	fc := setCookie(rec, "__inid_flow_"+q.Get("state"))
	for _, attr := range []string{"; Path=/api/inid", "; Max-Age=600", "; HttpOnly", "; SameSite=Lax", "; Secure"} {
		if !strings.Contains(fc, attr) {
			t.Errorf("flow cookie %q lacks %q", fc, attr)
		}
	}
	_, fl, _ := signIn(t, c, "return_to=/dashboard")
	check(t, "returnTo", fl.ReturnTo, "/dashboard")
	q2, fl2, _ := signIn(t, c, "return_to=/x")
	sum2 := sha256.Sum256([]byte(fl2.Verifier))
	check(t, "PKCE challenge", q2.Get("code_challenge"), base64.RawURLEncoding.EncodeToString(sum2[:]))
	check(t, "flow nonce", q2.Get("nonce"), fl2.Nonce)

	for _, bad := range []string{"//evil.com", "/%5Cevil.com", "https://evil.com", ""} {
		_, fl, _ := signIn(t, c, "return_to="+bad)
		check(t, "sanitized "+bad, fl.ReturnTo, "/")
	}
}

func TestSignInPromptAndEmbed(t *testing.T) {
	f := newFake(t)
	c := newClient(t, f)
	q, _, _ := signIn(t, c, "return_to=/", "__inid_out=1")
	check(t, "prompt after signing out", q.Get("prompt"), "login")

	q, fl, _ := signIn(t, c, "return_to=/home&display=embed&page=/signin-page")
	check(t, "embed", []string{q.Get("display"), q.Get("prompt")}, []string{"embed", "login"})
	check(t, "embed flow", []any{fl.Embed, fl.Page, fl.ReturnTo}, []any{true, "/signin-page", "/home"})

	// Back from Google inside the frame: on with the same sign-in at InID
	rec, _ := run(c, get("/api/inid/signin?display=embed&continue="+url.QueryEscape("request=r1&session=s1&from=google&lang=es&evil=1")))
	loc, _ := url.Parse(rec.Header().Get("Location"))
	check(t, "continue path", loc.Path, "/oauth/authorize/continue")
	check(t, "continue query", loc.Query().Encode(), "display=embed&from=google&lang=es&request=r1&session=s1")
}

// ---------- 2. callback ----------

func TestCallback(t *testing.T) {
	f := newFake(t)
	c := newClient(t, f)
	_, fl, flowCookie := signIn(t, c, "return_to=/dashboard")
	f.nextNonce = fl.Nonce
	rec, _ := run(c, get("/api/inid/callback?code=c1&state="+fl.State, flowCookie, "__inid_out=1"))
	check(t, "status", rec.Code, 302)
	check(t, "to returnTo", rec.Header().Get("Location"), "/dashboard")

	form := f.tokenForms[0]
	check(t, "grant", []string{form.Get("grant_type"), form.Get("code"), form.Get("redirect_uri"), form.Get("code_verifier")},
		[]string{"authorization_code", "c1", "https://app.example/api/inid/callback", fl.Verifier})
	check(t, "basic auth", f.tokenAuth[0], "Basic "+base64.StdEncoding.EncodeToString([]byte("pk_test_app:sk_test_secret")))

	if s := setCookie(rec, "__inid_session"); !strings.Contains(s, "Max-Age=2592000") || !strings.Contains(s, "; Path=/;") || strings.HasPrefix(s, "__inid_session=;") {
		t.Errorf("session cookie: %q", s)
	}
	check(t, "refresh cookie", strings.SplitN(setCookie(rec, "__inid_refresh"), ";", 2)[0], "__inid_refresh=rt_new")
	if !strings.Contains(setCookie(rec, "__inid_out"), "Max-Age=0") {
		t.Errorf("__inid_out not cleared: %q", setCookie(rec, "__inid_out"))
	}
	if !strings.Contains(setCookie(rec, "__inid_flow_"+fl.State), "Max-Age=0") {
		t.Error("flow cookie not cleared")
	}

	// A nonce that isn't this flow's: refused
	_, fl, flowCookie = signIn(t, c, "return_to=/dashboard")
	f.nextNonce = "someone-elses"
	rec, _ = run(c, get("/api/inid/callback?code=c2&state="+fl.State, flowCookie))
	check(t, "wrong nonce", rec.Code, 400)
	check(t, "no session", setCookie(rec, "__inid_session"), "")

	// A state with no flow of its own: home, without asking InID
	asked := len(f.tokenForms)
	_, _, flowCookie = signIn(t, c, "return_to=/dashboard")
	rec, _ = run(c, get("/api/inid/callback?code=c3&state=other", flowCookie))
	check(t, "state mismatch", []any{rec.Code, rec.Header().Get("Location"), len(f.tokenForms)}, []any{302, "/", asked})
}

func TestCallbackEmbedded(t *testing.T) {
	f := newFake(t)
	c := newClient(t, f)
	_, fl, flowCookie := signIn(t, c, "return_to=/a</script>&display=embed&page=/login")
	f.nextNonce = fl.Nonce
	rec, _ := run(c, get("/api/inid/callback?code=c1&state="+fl.State, flowCookie))
	check(t, "status", rec.Code, 200)
	check(t, "page", rec.Body.String(), `<!doctype html><meta charset="utf-8"><script>(window.top || window).location.replace("/a`+"\\"+"u003c"+`/script>")</script>`)
	if setCookie(rec, "__inid_session") == "" {
		t.Error("no session cookie")
	}

	// Back from Google: to the page with the form, which goes on where InID left it
	rec, _ = run(c, get("/api/inid/callback?inid_continue=abc&state="+fl.State, flowCookie))
	check(t, "resume", []any{rec.Code, rec.Header().Get("Location")}, []any{302, "/login?inid_continue=abc"})
}

// ---------- 3. renewal ----------

func TestRenewal(t *testing.T) {
	f := newFake(t)
	c := newClient(t, f)
	ending := f.sign(f.claims(30)) // within a minute of its end
	rec, s := run(c, get("/", "__inid_session="+ending, "__inid_refresh=rt_old", "other=1"))
	check(t, "refresh grant", []string{f.tokenForms[0].Get("grant_type"), f.tokenForms[0].Get("refresh_token")}, []string{"refresh_token", "rt_old"})
	check(t, "signed in", s.auth.IsSignedIn, true)
	newSession := strings.SplitN(setCookie(rec, "__inid_session"), ";", 2)[0]
	if newSession == "__inid_session="+ending || !strings.Contains(setCookie(rec, "__inid_refresh"), "rt_new") {
		t.Error("cookies not renewed")
	}
	// The same request sees the renewed session
	if !strings.Contains(s.cookie, newSession) || !strings.Contains(s.cookie, "__inid_refresh=rt_new") || !strings.Contains(s.cookie, "other=1") {
		t.Errorf("request cookies: %q", s.cookie)
	}

	// Fresh: no call to InID
	n := len(f.tokenForms)
	rec, s = run(c, get("/", "__inid_session="+f.sign(f.claims(600)), "__inid_refresh=rt"))
	check(t, "fresh", []any{s.auth.IsSignedIn, len(f.tokenForms), setCookie(rec, "__inid_session")}, []any{true, n, ""})
}

func TestRenewalRefused(t *testing.T) {
	f := newFake(t)
	c := newClient(t, f)
	f.tokenStatus = 400
	rec, s := run(c, get("/", "__inid_session="+f.sign(f.claims(30)), "__inid_refresh=rt_old"))
	check(t, "signed out", s.auth.IsSignedIn, false)
	for _, name := range []string{"__inid_session", "__inid_refresh"} {
		if !strings.Contains(setCookie(rec, name), "Max-Age=0") {
			t.Errorf("%s not cleared", name)
		}
	}
	check(t, "request cookies", s.cookie, "")
}

func TestRenewalUnreachable(t *testing.T) {
	f := newFake(t)
	c := newClient(t, f)
	f.tokenDown = true
	rec, s := run(c, get("/", "__inid_session="+f.sign(f.claims(30)), "__inid_refresh=rt_old"))
	check(t, "still valid stays", []any{s.auth.IsSignedIn, setCookie(rec, "__inid_session")}, []any{true, ""})
	_, s = run(c, get("/", "__inid_session="+f.sign(f.claims(-5)), "__inid_refresh=rt_old"))
	check(t, "expired doesn't", s.auth.IsSignedIn, false)

	f.tokenDown, f.tokenStatus = false, 503
	_, s = run(c, get("/", "__inid_session="+f.sign(f.claims(30)), "__inid_refresh=rt_old"))
	check(t, "5xx keeps", s.auth.IsSignedIn, true)
}

// ---------- 4. signout ----------

func TestSignOut(t *testing.T) {
	f := newFake(t)
	c := newClient(t, f)
	req := httptest.NewRequest("POST", "https://app.example/api/inid/signout", nil)
	req.Header.Set("Cookie", "__inid_session=x; __inid_refresh=rt_1")
	rec, _ := run(c, req)
	check(t, "answer", []any{rec.Code, strings.TrimSpace(rec.Body.String()), rec.Header().Get("Cache-Control")}, []any{200, `{"ok":true}`, "no-store"})
	check(t, "revoked", []string{f.revoked[0].Get("token"), f.revoked[0].Get("token_type_hint")}, []string{"rt_1", "refresh_token"})
	check(t, "revoke auth", strings.HasPrefix(f.revokeAuth, "Basic "), true)
	for _, name := range []string{"__inid_session", "__inid_refresh"} {
		if !strings.Contains(setCookie(rec, name), "Max-Age=0") {
			t.Errorf("%s not cleared", name)
		}
	}
	out := setCookie(rec, "__inid_out")
	if !strings.HasPrefix(out, "__inid_out=1;") || !strings.Contains(out, "Max-Age=2592000") {
		t.Errorf("__inid_out: %q", out)
	}
}

// ---------- 5. /session ----------

func TestSessionRoute(t *testing.T) {
	f := newFake(t)
	c := newClient(t, f)
	rec, _ := run(c, get("/api/inid/session", "__inid_session="+f.sign(f.claims(600))))
	check(t, "cache-control", rec.Header().Get("Cache-Control"), "no-store")
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	user, _ := json.Marshal(body["user"])
	check(t, "user", string(user), `{"email":"ana@correo.co","emailVerified":true,"firstName":"Ana","id":"u1","lastName":"Gómez","name":"Ana Gómez","permissions":["orders:read"],"phone":"+573001234567","publicMetadata":{"plan":"pro"},"roles":["staff"]}`)
	check(t, "accountUrl", body["accountUrl"], f.srv.URL+"/account?client_id=pk_test_app")

	rec, _ = run(c, get("/api/inid/session"))
	check(t, "nobody", strings.TrimSpace(rec.Body.String()), `{"accountUrl":"`+f.srv.URL+`/account?client_id=pk_test_app","user":null}`)

	// Bare claims: nulls and empty lists, never missing fields
	bare := map[string]any{"iss": f.srv.URL, "aud": "pk_test_app", "sub": "u2", "exp": time.Now().Unix() + 600, "name": "Solo"}
	rec, _ = run(c, get("/api/inid/session", "__inid_session="+f.sign(bare)))
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	user, _ = json.Marshal(body["user"])
	check(t, "bare user", string(user), `{"email":null,"emailVerified":false,"firstName":null,"id":"u2","lastName":null,"name":"Solo","permissions":[],"phone":null,"publicMetadata":{},"roles":[]}`)

	// Renewal happens here too
	rec, _ = run(c, get("/api/inid/session", "__inid_session="+f.sign(f.claims(10)), "__inid_refresh=rt"))
	if setCookie(rec, "__inid_refresh") == "" {
		t.Error("/session didn't renew")
	}
	rec, _ = run(c, get("/api/inid/nothing"))
	check(t, "404", []any{rec.Code, strings.TrimSpace(rec.Body.String())}, []any{404, `{"error":"not_found"}`})
}

func TestSessionsRoute(t *testing.T) {
	f := newFake(t)
	c := newClient(t, f)
	rec, _ := run(c, get("/api/inid/sessions"))
	check(t, "anonymous", rec.Code, 401)
	cookie := "__inid_session=" + f.sign(f.claims(600))
	rec, _ = run(c, get("/api/inid/sessions", cookie))
	var body struct {
		Sessions []struct {
			ID      string
			Current bool
		}
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	check(t, "list", body.Sessions, []struct {
		ID      string
		Current bool
	}{{"s1", false}, {"s2", true}, {"s3", false}})

	req := httptest.NewRequest("DELETE", "https://app.example/api/inid/sessions?others=1", nil)
	req.Header.Set("Cookie", cookie)
	rec, _ = run(c, req)
	check(t, "others", []any{strings.TrimSpace(rec.Body.String()), f.deleted}, []any{`{"ended":2}`, []string{"s1", "s3"}})
	req = httptest.NewRequest("DELETE", "https://app.example/api/inid/sessions/s9", nil)
	req.Header.Set("Cookie", cookie)
	rec, _ = run(c, req)
	check(t, "one", []any{strings.TrimSpace(rec.Body.String()), f.deleted[2]}, []any{`{"ended":1}`, "s9"})
}

// ---------- 6. the gate ----------

func TestGate(t *testing.T) {
	f := newFake(t)
	c := newClient(t, f)
	protect := Protect(Path("/dashboard"), Rule{Path: "/admin", Role: "admin", Entrance: "team"}, Rule{Pattern: Regex(`^/orders`).Pattern, Permission: "orders:read"})

	rec, s := run(c, get("/admin/users?x=1"), protect)
	check(t, "to sign in", []any{rec.Code, rec.Header().Get("Location"), s.called}, []any{307, "https://app.example/api/inid/signin?return_to=%2Fadmin%2Fusers%3Fx%3D1&entrance=team", false})
	rec, _ = run(c, get("/dashboard"), protect)
	check(t, "no entrance", rec.Header().Get("Location"), "https://app.example/api/inid/signin?return_to=%2Fdashboard")
	_, s = run(c, get("/dashboardx"), protect)
	check(t, "not a subpath", []any{s.called, s.auth.IsSignedIn}, []any{true, false})
	rec, _ = run(c, get("/dashboard/a/b"), protect)
	check(t, "subpath", rec.Code, 307)
	rec, _ = run(c, get("/orders7"), protect)
	check(t, "regex", rec.Code, 307)

	ana := "__inid_session=" + f.sign(f.claims(600))
	rec, s = run(c, get("/admin", ana), protect)
	check(t, "403 without role", []any{rec.Code, rec.Body.String(), s.called}, []any{403, "Forbidden", false})
	_, s = run(c, get("/dashboard/x", ana), protect)
	check(t, "path-only rule lets anyone signed in", s.called, true)
	rec, s = run(c, get("/orders/7", ana), protect)
	check(t, "with permission", []any{rec.Code, s.auth.UserID, s.auth.Has(Check{Role: "staff"}), s.auth.Has(Check{Role: "admin"}), s.auth.Has(Check{})}, []any{200, "u1", true, false, true})
	check(t, "user", []any{*s.auth.User.Name, s.auth.User.Has(Check{Role: "staff", Permission: "orders:read"}), s.auth.User.Has(Check{Role: "staff", Permission: "x"})}, []any{"Ana Gómez", true, false})

	rec, _ = run(c, get("/?state=inidg_abc&code=g&scope=email"), protect)
	check(t, "Google return", []any{rec.Code, rec.Header().Get("Location")}, []any{307, f.srv.URL + "/oauth/google/callback?state=inidg_abc&code=g&scope=email"})
	rec, _ = run(c, get("/?state=inidg_abc&error=access_denied"))
	check(t, "Google error return", rec.Code, 307)
	_, s = run(c, get("/?state=other&code=g"))
	check(t, "not Google's", s.called, true)

	rec, _ = run(c, get("/anything"), ProtectFunc(func(r *http.Request) bool { return r.URL.Path == "/anything" }))
	check(t, "ProtectFunc", rec.Code, 307)
	_, s = run(c, get("/api/inid/session"), SkipRoutes())
	check(t, "SkipRoutes", s.called, true)
	anon := FromContext(get("/").Context())
	check(t, "FromContext outside", []any{anon.IsSignedIn, anon.Has(Check{}), anon.Has(Check{Role: "staff"})}, []any{false, false, false})
}

// ---------- 7. webhooks ----------

func TestWebhook(t *testing.T) {
	f := newFake(t)
	c := newClient(t, f)
	body := []byte(`{"type":"session.ended","sub":"u1","sid":"s1","created_at":"2026-11-16T00:00:00Z"}`)
	sign := func(secret string, at int64) string {
		m := hmac.New(sha256.New, []byte(secret))
		m.Write([]byte(fmt.Sprintf("%d.%s", at, body)))
		return fmt.Sprintf("t=%d,v1=%s", at, hex.EncodeToString(m.Sum(nil)))
	}
	now := time.Now().Unix()
	ev, err := c.VerifyWebhook(body, sign("whsec_test", now))
	if err != nil {
		t.Fatal(err)
	}
	check(t, "event", []any{ev.Type, ev.Sub, ev.Sid, ev.CreatedAt, ev.Raw["sid"]}, []any{"session.ended", "u1", "s1", "2026-11-16T00:00:00Z", "s1"})
	for name, header := range map[string]string{
		"wrong secret": sign("whsec_other", now),
		"too old":      sign("whsec_test", now-301),
		"future":       sign("whsec_test", now+301),
		"malformed":    "garbage",
		"no v1":        fmt.Sprintf("t=%d", now),
		"no t":         "v1=" + strings.Repeat("0", 64),
		"empty":        "",
		"not hex":      fmt.Sprintf("t=%d,v1=zz", now),
	} {
		if _, err := c.VerifyWebhook(body, header); !errors.Is(err, ErrInvalidSignature) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := c.VerifyWebhook([]byte(`{"type":"x"}`), sign("whsec_test", now)); !errors.Is(err, ErrInvalidSignature) {
		t.Error("another body passed")
	}
}

// ---------- 8. ID token verification ----------

func TestVerifyIDToken(t *testing.T) {
	f := newFake(t)
	c := newClient(t, f)
	good := f.claims(600)
	if s, err := c.VerifyBearer("Bearer " + f.sign(good)); err != nil || s.User.ID != "u1" {
		t.Fatalf("good token: %v", err)
	}
	with := func(k string, v any) map[string]any {
		m := f.claims(600)
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
		return m
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	tampered := strings.Split(f.sign(good), ".")
	tampered[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"x"}`))
	cases := map[string]string{
		"wrong aud":     f.sign(with("aud", "pk_test_other")),
		"wrong iss":     f.sign(with("iss", "https://evil.example")),
		"no sub":        f.sign(with("sub", nil)),
		"bad signature": signWith(other, "k1", good),
		"tampered":      strings.Join(tampered, "."),
		"unknown kid":   signWith(f.key, "k-unknown", good),
		"expired":       f.sign(f.claims(-1)),
		"not a jwt":     "abc.def",
	}
	for name, token := range cases {
		if _, err := c.VerifyBearer(token); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// An expired one still verifies, flagged, so the session can be renewed from it
	v, _ := c.verifyIDToken(f.sign(f.claims(-1)), "", false)
	check(t, "expired flagged", v != nil && v.expired, true)
	// alg none is never accepted
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"k1"}`))
	cl, _ := json.Marshal(good)
	if v, _ := c.verifyIDToken(h+"."+base64.RawURLEncoding.EncodeToString(cl)+".", "", false); v != nil {
		t.Error("alg none accepted")
	}
}

func TestKeyCache(t *testing.T) {
	f := newFake(t)
	c := newClient(t, f)
	now := time.Now()
	c.now = func() time.Time { return now }
	tok := f.sign(f.claims(600))
	for i := 0; i < 3; i++ {
		_, _ = c.VerifyBearer(tok)
	}
	check(t, "cached", f.jwksHits, 1)
	// Unknown kids: at most once a second, once per kid
	unknown := func(kid string) { _, _ = c.VerifyBearer(signWith(f.key, kid, f.claims(600))) }
	unknown("new1") // the first unknown kid is looked up at once (InID just rotated)
	check(t, "rotated", f.jwksHits, 2)
	unknown("new2")
	check(t, "within a second", f.jwksHits, 2)
	now = now.Add(2 * time.Second)
	unknown("new2")
	check(t, "refetched", f.jwksHits, 3)
	now = now.Add(2 * time.Second)
	unknown("new2")
	check(t, "missed kid remembered", f.jwksHits, 3)
	now = now.Add(2 * time.Hour)
	_, _ = c.VerifyBearer(tok)
	check(t, "an hour later", f.jwksHits, 4)
}
