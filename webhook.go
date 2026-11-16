package inid

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

// WebhookEvent is a verified event from InID. Raw has every field, for those not listed.
type WebhookEvent struct {
	// user.created, user.updated, user.deleted, session.created, session.ended,
	// subscription.cancel_requested, customer.logged_out, customer.registered, checkout.abandoned
	Type      string `json:"type"`
	CreatedAt string `json:"created_at"`
	Sub       string `json:"sub,omitempty"`
	// A one-time token to exchange for the person's data (user.deleted, customer.registered…)
	Token        string         `json:"token,omitempty"`
	Sid          string         `json:"sid,omitempty"`
	Subscription string         `json:"subscription,omitempty"`
	Raw          map[string]any `json:"-"`
}

// ErrInvalidSignature is returned for a webhook InID didn't sign (or signed too long ago).
var ErrInvalidSignature = errors.New("inid: invalid webhook signature")

const webhookTolerance = 300 // seconds

// VerifyWebhook checks a webhook's InID-Signature header against the raw body (as received,
// before any JSON parsing) with the client's WebhookSecret, and returns the event.
func (c *Client) VerifyWebhook(body []byte, header string) (*WebhookEvent, error) {
	if c.cfg.WebhookSecret == "" {
		return nil, errors.New("inid: INID_WEBHOOK_SECRET is missing")
	}
	return VerifyWebhook(c.cfg.WebhookSecret, body, header, c.now())
}

// VerifyWebhook is the client method without a client, for a server that only takes webhooks.
func VerifyWebhook(secret string, body []byte, header string, now time.Time) (*WebhookEvent, error) {
	parts := map[string]string{}
	for _, p := range strings.Split(header, ",") {
		if k, v, ok := strings.Cut(strings.TrimSpace(p), "="); ok {
			parts[k] = v
		}
	}
	at, err := strconv.ParseInt(parts["t"], 10, 64)
	if err != nil || at == 0 || parts["v1"] == "" {
		return nil, ErrInvalidSignature
	}
	if d := now.Unix() - at; d > webhookTolerance || d < -webhookTolerance {
		return nil, ErrInvalidSignature
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(at, 10) + "."))
	mac.Write(body)
	given, err := hex.DecodeString(parts["v1"])
	if err != nil || !hmac.Equal(given, mac.Sum(nil)) {
		return nil, ErrInvalidSignature
	}
	var event WebhookEvent
	if err := json.Unmarshal(body, &event); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(body, &event.Raw)
	return &event, nil
}
