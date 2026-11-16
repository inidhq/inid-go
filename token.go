package inid

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"sync"
	"time"
)

// keyCache holds InID's public keys for an hour. An unknown kid (InID rotated its key) is
// looked up at once, but once per kid and at most once a second, so tokens with made-up kids
// can't make the app ask InID again and again.
type keyCache struct {
	mu      sync.Mutex
	loaded  bool
	at      time.Time
	keys    map[string]*rsa.PublicKey
	missed  map[string]bool
	askedAt time.Time
}

func (c *Client) keyFor(kid string) (*rsa.PublicKey, error) {
	k := c.keys
	k.mu.Lock()
	defer k.mu.Unlock()
	now := c.now()
	if k.loaded && now.Sub(k.at) < time.Hour {
		if key, ok := k.keys[kid]; ok {
			return key, nil
		}
		if k.missed[kid] || now.Sub(k.askedAt) < time.Second {
			return nil, nil
		}
		k.missed[kid] = true
		if len(k.missed) > 100 {
			k.missed = map[string]bool{}
		}
	}
	// Only lookups after the first load count toward "once a second"
	askedAt := time.Time{}
	if k.loaded {
		askedAt = now
	}
	res, err := c.http.Get(c.cfg.Issuer + "/.well-known/jwks.json")
	if err != nil {
		return nil, &Error{Code: "jwks_unavailable"}
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, &Error{Code: "jwks_unavailable", Status: res.StatusCode}
	}
	var set struct {
		Keys []struct {
			Kty, Kid, N, E string
		} `json:"keys"`
	}
	if err := json.NewDecoder(res.Body).Decode(&set); err != nil {
		return nil, &Error{Code: "jwks_unavailable", Status: res.StatusCode}
	}
	keys := map[string]*rsa.PublicKey{}
	for _, j := range set.Keys {
		if j.Kty != "RSA" {
			continue
		}
		n, err1 := base64.RawURLEncoding.DecodeString(j.N)
		e, err2 := base64.RawURLEncoding.DecodeString(j.E)
		if err1 != nil || err2 != nil || len(e) == 0 || len(e) > 4 {
			continue
		}
		keys[j.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	k.loaded, k.at, k.keys, k.askedAt = true, now, keys, askedAt
	return keys[kid], nil
}

// verified is an ID token InID signed for this app. An expired one still comes back
// (expired = true) so the session can be renewed from it; it never counts as signed in.
type verified struct {
	claims  map[string]any
	exp     int64
	expired bool
}

// verifyIDToken returns nil for any token that isn't InID's for this app, and an error only
// when InID's keys can't be fetched.
func (c *Client) verifyIDToken(token, nonce string, checkNonce bool) (*verified, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil
	}
	var header struct {
		Alg string `json:"alg"`
		Kid any    `json:"kid"`
	}
	if !decodePart(parts[0], &header) || header.Alg != "RS256" {
		return nil, nil
	}
	kid, ok := header.Kid.(string)
	if !ok {
		return nil, nil
	}
	key, err := c.keyFor(kid)
	if err != nil || key == nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig) != nil {
		return nil, nil
	}
	var claims map[string]any
	if !decodePart(parts[1], &claims) {
		return nil, nil
	}
	iss, _ := claims["iss"].(string)
	aud, _ := claims["aud"].(string)
	_, subOK := claims["sub"].(string)
	exp, expOK := claims["exp"].(float64)
	if iss != c.cfg.Issuer || aud != c.cfg.PublishableKey || !subOK || !expOK {
		return nil, nil
	}
	if checkNonce {
		if n, _ := claims["nonce"].(string); n != nonce {
			return nil, nil
		}
	}
	return &verified{claims: claims, exp: int64(exp), expired: int64(exp) <= c.now().Unix()}, nil
}

func decodePart(part string, into any) bool {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(part, "="))
	return err == nil && json.Unmarshal(raw, into) == nil
}

// VerifyBearer checks an ID token a native app sent its backend (Authorization: Bearer …):
// signed by InID, for this app, not expired. Pass the token without the "Bearer " prefix.
func (c *Client) VerifyBearer(token string) (*Session, error) {
	token = strings.TrimSpace(strings.TrimPrefix(token, "Bearer "))
	v, err := c.verifyIDToken(token, "", false)
	if err != nil {
		return nil, err
	}
	if v == nil || v.expired {
		return nil, ErrInvalidToken
	}
	return sessionOf(v), nil
}
