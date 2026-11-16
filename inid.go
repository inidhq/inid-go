// Package inid is sign-in with InID for Go servers: the routes that sign people in and out
// (under /api/inid), the session in its cookies (renewed before it ends), a middleware that
// guards paths by sign-in, role or permission, webhook verification and the app API.
//
// The app is an OpenID Connect client of InID: its publishable key is the client id and its
// secret key the client secret. The session is InID's signed ID token in a cookie, checked
// with InID's public keys (never with a call to InID); the refresh token renews it.
package inid

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// Config is what an app tells the SDK. Empty fields take their defaults.
type Config struct {
	PublishableKey string // pk_test_… / pk_live_…
	SecretKey      string // sk_…
	Issuer         string // default https://id.inid.co
	// The app's own origin (https://app.example.com), when requests don't say it (behind proxies)
	AppURL        string
	APIPath       string // default /api/inid
	Scope         string // default "openid profile email phone"
	WebhookSecret string // whsec_…, only to verify webhooks
	// Used for every call to InID; default a client with a 10 s timeout
	HTTPClient *http.Client
}

// Client is one InID app. It is safe for concurrent use.
type Client struct {
	cfg  Config
	http *http.Client
	now  func() time.Time
	keys *keyCache
}

// Error is an error from InID or from checking what it sent.
type Error struct {
	Code   string
	Status int // HTTP status InID answered, 0 when none
}

func (e *Error) Error() string {
	if e.Status != 0 {
		return fmt.Sprintf("inid: %s (status %d)", e.Code, e.Status)
	}
	return "inid: " + e.Code
}

// ErrInvalidToken is returned by VerifyBearer for any token that isn't a valid, current ID token.
var ErrInvalidToken = errors.New("inid: invalid token")

const (
	cookieSession = "__inid_session"
	cookieRefresh = "__inid_refresh"
	cookieFlow    = "__inid_flow"
	cookieOut     = "__inid_out"

	cookieMaxAge = 30 * 24 * 3600
	flowMaxAge   = 600
	// A session with less than this left is renewed now, not in the middle of the next request
	renewBefore = 60
)

// New checks the config and makes a client. Missing or malformed keys fail here, at startup.
func New(cfg Config) (*Client, error) {
	if cfg.Issuer == "" {
		cfg.Issuer = "https://id.inid.co"
	}
	cfg.Issuer = strings.TrimSuffix(cfg.Issuer, "/")
	if cfg.APIPath == "" {
		cfg.APIPath = "/api/inid"
	}
	cfg.APIPath = strings.TrimSuffix(cfg.APIPath, "/")
	if cfg.Scope == "" {
		cfg.Scope = "openid profile email phone"
	}
	cfg.AppURL = strings.TrimSuffix(cfg.AppURL, "/")
	if !strings.HasPrefix(cfg.PublishableKey, "pk_") {
		return nil, errors.New("inid: INID_PUBLISHABLE_KEY is missing: set it to your publishable key (pk_...)")
	}
	if !strings.HasPrefix(cfg.SecretKey, "sk_") {
		return nil, errors.New("inid: INID_SECRET_KEY is missing: set it to your secret key (sk_...)")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	return &Client{cfg: cfg, http: hc, now: time.Now, keys: &keyCache{missed: map[string]bool{}}}, nil
}

// NewFromEnv makes a client from INID_PUBLISHABLE_KEY, INID_SECRET_KEY, INID_ISSUER,
// INID_APP_URL and INID_WEBHOOK_SECRET.
func NewFromEnv() (*Client, error) {
	return New(Config{
		PublishableKey: os.Getenv("INID_PUBLISHABLE_KEY"),
		SecretKey:      os.Getenv("INID_SECRET_KEY"),
		Issuer:         os.Getenv("INID_ISSUER"),
		AppURL:         os.Getenv("INID_APP_URL"),
		WebhookSecret:  os.Getenv("INID_WEBHOOK_SECRET"),
	})
}

// Config returns the effective configuration (with defaults filled in).
func (c *Client) Config() Config { return c.cfg }
