package inid

import "slices"

// User is the signed-in person, from the ID token. It serializes with the same camelCase JSON
// the browser components expect.
type User struct {
	// The person's id at this app (InID gives each app its own)
	ID            string  `json:"id"`
	FirstName     *string `json:"firstName"`
	LastName      *string `json:"lastName"`
	Name          *string `json:"name"`
	Email         *string `json:"email"`
	EmailVerified bool    `json:"emailVerified"`
	Phone         *string `json:"phone"` // E.164
	// The app's roles for this person and what they allow; empty when the app has no roles
	Roles          []string       `json:"roles"`
	Permissions    []string       `json:"permissions"`
	PublicMetadata map[string]any `json:"publicMetadata"`
	// The team they're working in now (apps with teams), with their role there; nil: none
	Team *Team `json:"team"`
}

// Team is the person's active team, chosen per session: their role there and what it allows.
type Team struct {
	ID          string   `json:"id"`
	Slug        string   `json:"slug"`
	Name        string   `json:"name"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
}

// Check asks for a role, a role in the active team, a permission, or several of them.
type Check struct {
	Role       string
	Permission string
	TeamRole   string
}

// Has is true when the user has everything asked: the role, the role in their active team,
// the permission (from their app role or their team role). With nothing asked, any signed-in
// user passes: a protect rule with only a path needs no role.
func (u *User) Has(check Check) bool {
	if u == nil {
		return false
	}
	if check.Role != "" && !slices.Contains(u.Roles, check.Role) {
		return false
	}
	if check.TeamRole != "" && (u.Team == nil || u.Team.Role != check.TeamRole) {
		return false
	}
	if check.Permission != "" && !slices.Contains(u.Permissions, check.Permission) &&
		(u.Team == nil || !slices.Contains(u.Team.Permissions, check.Permission)) {
		return false
	}
	return true
}

// Session is a verified sign-in.
type Session struct {
	User      *User
	ExpiresAt int64 // seconds since 1970; renewed before then
	Claims    map[string]any
}

// Auth is who is signed in, for a handler (see FromContext).
type Auth struct {
	IsSignedIn bool
	UserID     string // "" when nobody is signed in
	User       *User
	Session    *Session
}

// Has is true when someone is signed in with the role and/or permission asked.
func (a *Auth) Has(check Check) bool { return a != nil && a.User.Has(check) }

func authOf(s *Session) *Auth {
	if s == nil {
		return &Auth{}
	}
	return &Auth{IsSignedIn: true, UserID: s.User.ID, User: s.User, Session: s}
}

func sessionOf(v *verified) *Session {
	return &Session{User: userOf(v.claims), ExpiresAt: v.exp, Claims: v.claims}
}

func userOf(claims map[string]any) *User {
	text := func(key string) *string {
		if s, ok := claims[key].(string); ok && s != "" {
			return &s
		}
		return nil
	}
	sub, _ := claims["sub"].(string)
	u := &User{
		ID:          sub,
		FirstName:   text("given_name"),
		LastName:    text("family_name"),
		Email:       text("email"),
		Phone:       text("phone_number"),
		Roles:       stringsOf(claims["roles"]),
		Permissions: stringsOf(claims["permissions"]),
		Team:        teamOf(claims["team"]),
	}
	u.EmailVerified, _ = claims["email_verified"].(bool)
	var parts []string
	for _, p := range []*string{u.FirstName, u.LastName} {
		if p != nil {
			parts = append(parts, *p)
		}
	}
	if len(parts) > 0 {
		name := parts[0]
		if len(parts) == 2 {
			name += " " + parts[1]
		}
		u.Name = &name
	} else {
		u.Name = text("name")
	}
	if meta, ok := claims["public_metadata"].(map[string]any); ok {
		u.PublicMetadata = meta
	} else {
		u.PublicMetadata = map[string]any{}
	}
	return u
}

// stringsOf keeps the strings of a JSON list; empty (never nil) otherwise.
func stringsOf(v any) []string {
	out := []string{}
	if list, ok := v.([]any); ok {
		for _, item := range list {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// teamOf is the ID token's team claim; nil when it's missing or malformed.
func teamOf(claim any) *Team {
	t, ok := claim.(map[string]any)
	if !ok {
		return nil
	}
	id, okID := t["id"].(string)
	role, okRole := t["role"].(string)
	if !okID || !okRole {
		return nil
	}
	slug, _ := t["slug"].(string)
	name, _ := t["name"].(string)
	return &Team{ID: id, Slug: slug, Name: name, Role: role, Permissions: stringsOf(t["permissions"])}
}
