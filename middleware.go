package inid

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Rule is a path (or pattern) that needs someone signed in, and optionally a role or a
// permission. Entrance is the door its sign-in goes through (an entrance key from the panel).
//
//	inid.Path("/dashboard")
//	inid.Regex(`^/reports/\d+$`)
//	inid.Rule{Path: "/admin", Role: "admin"}
type Rule struct {
	// Matches itself and its subpaths: "/admin" matches /admin and /admin/x, not /adminx
	Path string
	// Used instead of Path when set
	Pattern    *regexp.Regexp
	Role       string
	Permission string
	Entrance   string
}

// Path is a rule for a path and its subpaths.
func Path(p string) Rule { return Rule{Path: p} }

// Regex is a rule for the paths matching a regular expression. It panics on a bad expression,
// like regexp.MustCompile, since rules are set at startup.
func Regex(expr string) Rule { return Rule{Pattern: regexp.MustCompile(expr)} }

func (r Rule) matches(path string) bool {
	if r.Pattern != nil {
		return r.Pattern.MatchString(path)
	}
	if r.Path == "" {
		return false
	}
	prefix := r.Path
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return path == r.Path || strings.HasPrefix(path, prefix)
}

type gateOptions struct {
	rules      []Rule
	protectFn  func(*http.Request) bool
	skipRoutes bool
}

// Option changes what the middleware does.
type Option func(*gateOptions)

// Protect adds rules: who isn't signed in is sent to sign in; who lacks a role or permission
// gets 403.
func Protect(rules ...Rule) Option {
	return func(o *gateOptions) { o.rules = append(o.rules, rules...) }
}

// ProtectFunc protects every request the function says yes to (sign-in only).
func ProtectFunc(fn func(*http.Request) bool) Option {
	return func(o *gateOptions) { o.protectFn = fn }
}

// SkipRoutes leaves the api path routes to a Handler mounted elsewhere.
func SkipRoutes() Option {
	return func(o *gateOptions) { o.skipRoutes = true }
}

type ctxKey struct{}

// FromContext is who is signed in for this request (set by the middleware). Never nil.
func FromContext(ctx context.Context) *Auth {
	if a, ok := ctx.Value(ctxKey{}).(*Auth); ok {
		return a
	}
	return &Auth{}
}

// WithAuth puts an Auth in a context (for tests of the app's own handlers).
func WithAuth(ctx context.Context, a *Auth) context.Context {
	return context.WithValue(ctx, ctxKey{}, a)
}

// Gate is Middleware in the shape chi, gorilla/mux and others take: r.Use(client.Gate(...)).
func (c *Client) Gate(opts ...Option) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler { return c.Middleware(next, opts...) }
}

// Middleware answers InID's routes under the api path, keeps the session fresh, guards the
// protected paths, and puts the Auth in the request's context (FromContext).
func (c *Client) Middleware(next http.Handler, opts ...Option) http.Handler {
	o := &gateOptions{}
	for _, opt := range opts {
		opt(o)
	}
	apiPath := c.cfg.APIPath
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == apiPath || strings.HasPrefix(path, apiPath+"/") {
			if o.skipRoutes {
				next.ServeHTTP(w, r)
			} else {
				c.serveRoutes(w, r)
			}
			return
		}
		// Back from Google on the app's own domain: Google's answer is for InID, so the person
		// goes straight on there
		q := r.URL.Query()
		if strings.HasPrefix(q.Get("state"), "inidg_") && (q.Has("code") || q.Has("error")) {
			http.Redirect(w, r, c.cfg.Issuer+"/oauth/google/callback?"+r.URL.RawQuery, http.StatusTemporaryRedirect)
			return
		}
		res, err := c.readSession(r, true, c.secure(r))
		if err != nil {
			http.Error(w, "InID is unavailable", http.StatusBadGateway)
			return
		}
		addCookies(w, res.setCookies)

		var matched []Rule
		if o.protectFn != nil && o.protectFn(r) {
			matched = append(matched, Path("/"))
		}
		for _, rule := range o.rules {
			if rule.matches(path) {
				matched = append(matched, rule)
			}
		}
		if res.session == nil && len(matched) > 0 {
			to := "return_to=" + url.QueryEscape(r.URL.RequestURI())
			for _, rule := range matched {
				if rule.Entrance != "" {
					to += "&entrance=" + url.QueryEscape(rule.Entrance)
					break
				}
			}
			redirect(w, c.origin(r)+apiPath+"/signin?"+to, http.StatusTemporaryRedirect)
			return
		}
		if res.session != nil {
			for _, rule := range matched {
				// Signed in, without the role or permission the path needs
				if !res.session.User.Has(Check{Role: rule.Role, Permission: rule.Permission}) {
					w.Header().Set("Content-Type", "text/plain; charset=utf-8")
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write([]byte("Forbidden"))
					return
				}
			}
		}
		// The rest of this request sees the renewed cookies too
		if res.cookieHeader != nil {
			r = r.Clone(r.Context())
			r.Header.Set("Cookie", *res.cookieHeader)
		}
		next.ServeHTTP(w, r.WithContext(WithAuth(r.Context(), authOf(res.session))))
	})
}
