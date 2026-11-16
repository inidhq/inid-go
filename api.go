package inid

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
)

// appAPI calls InID's app API with the secret key. out may be nil.
func (c *Client) appAPI(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.Issuer+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.SecretKey)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode < 200 || res.StatusCode > 299 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		if e.Error == "" {
			e.Error = "request_failed"
		}
		return &Error{Code: e.Error, Status: res.StatusCode}
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// AppUser is a user as the app API returns it (GET /v1/users/{sub}).
type AppUser struct {
	ID              string         `json:"id"`
	FirstName       *string        `json:"firstName"`
	LastName        *string        `json:"lastName"`
	Email           *string        `json:"email"`
	EmailVerified   bool           `json:"emailVerified"`
	Phone           *string        `json:"phone"`
	Role            *string        `json:"role"`
	AuthorizedAt    *string        `json:"authorizedAt"`
	Scopes          []string       `json:"scopes"`
	PublicMetadata  map[string]any `json:"publicMetadata,omitempty"`
	PrivateMetadata map[string]any `json:"privateMetadata,omitempty"`
}

// GetUser is what the app may know about one of its users, by id (sub).
func (c *Client) GetUser(ctx context.Context, sub string) (*AppUser, error) {
	var u AppUser
	if err := c.appAPI(ctx, "GET", "/v1/users/"+url.PathEscape(sub), nil, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

// SetRole gives a user one of the app's roles; "" puts them back on the default role.
func (c *Client) SetRole(ctx context.Context, sub, role string) error {
	var r *string
	if role != "" {
		r = &role
	}
	return c.appAPI(ctx, "PUT", "/v1/users/"+url.PathEscape(sub)+"/role", map[string]*string{"role": r}, nil)
}

// Metadata is the app's own data about a user. Each one given replaces the previous one;
// nil leaves it as it is. The public one travels in the ID token.
type Metadata struct {
	Public  map[string]any `json:"publicMetadata,omitempty"`
	Private map[string]any `json:"privateMetadata,omitempty"`
}

// SetMetadata replaces a user's public and/or private metadata.
func (c *Client) SetMetadata(ctx context.Context, sub string, m Metadata) error {
	return c.appAPI(ctx, "PATCH", "/v1/users/"+url.PathEscape(sub)+"/metadata", m, nil)
}

// RoleInfo is one of the app's roles.
type RoleInfo struct {
	Key         string   `json:"key"`
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}

// Roles is the app's roles, its default role and its entrances.
type Roles struct {
	Roles       []RoleInfo `json:"roles"`
	DefaultRole *string    `json:"defaultRole"`
	Entrances   []struct {
		Key  string `json:"key"`
		Name string `json:"name"`
	} `json:"entrances"`
}

// Roles lists the app's roles (set in InID's panel).
func (c *Client) Roles(ctx context.Context) (*Roles, error) {
	var r Roles
	if err := c.appAPI(ctx, "GET", "/v1/roles", nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Invitation lets someone in by email (even when the app is access-list only), with a role.
type Invitation struct {
	Email string `json:"email"`
	Role  string `json:"role,omitempty"`
}

// Invite invites one person, or several at once (up to 200), and returns InID's answer
// ({"invited", "failed"} for several).
func (c *Client) Invite(ctx context.Context, invitations ...Invitation) (map[string]any, error) {
	var in any = map[string]any{"invitations": invitations}
	if len(invitations) == 1 {
		in = invitations[0]
	}
	out := map[string]any{}
	if err := c.appAPI(ctx, "POST", "/v1/invitations", in, &out); err != nil {
		return nil, err
	}
	return out, nil
}
