package inid

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	safePath  = regexp.MustCompile(`^/[^/\\]`)
	stateName = regexp.MustCompile(`^[\w-]{1,64}$`)
	teamsRest = regexp.MustCompile(`^(/[\w-]{1,80}){0,4}$`)
)

// safeReturn keeps a path in the app itself, never another site.
func safeReturn(to string) string {
	if to == "/" || safePath.MatchString(to) {
		return to
	}
	return "/"
}

type flow struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
	ReturnTo string `json:"returnTo"`
	Embed    bool   `json:"embed,omitempty"`
	Page     string `json:"page,omitempty"`
}

// Handler answers the routes under the api path (signin, callback, signout, session,
// sessions, team, teams). Mount it at the api path: mux.Handle("/api/inid/", client.Handler()).
// Middleware answers them too, so mounting it is only needed without the middleware.
func (c *Client) Handler() http.Handler {
	return http.HandlerFunc(c.serveRoutes)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func addCookies(w http.ResponseWriter, cookies []string) {
	for _, c := range cookies {
		w.Header().Add("Set-Cookie", c)
	}
}

func redirect(w http.ResponseWriter, to string, status int, cookies ...string) {
	addCookies(w, cookies)
	w.Header().Set("Location", to)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
}

// leaveFrame is a tiny page that sends the whole window on, out of InID's embedded form.
func leaveFrame(w http.ResponseWriter, to string, cookies ...string) {
	addCookies(w, cookies)
	var target bytes.Buffer
	enc := json.NewEncoder(&target)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(to)
	// "<" escaped so the address can't close the script
	escaped := strings.ReplaceAll(strings.TrimSpace(target.String()), "<", "\\"+"u003c")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(200)
	_, _ = w.Write([]byte(`<!doctype html><meta charset="utf-8"><script>(window.top || window).location.replace(` + escaped + `)</script>`))
}

func (c *Client) serveRoutes(w http.ResponseWriter, r *http.Request) {
	apiPath := c.cfg.APIPath
	action := ""
	if strings.HasPrefix(r.URL.Path, apiPath+"/") {
		action = r.URL.Path[len(apiPath)+1:]
	}
	switch {
	case r.Method == "GET" && action == "signin":
		c.signIn(w, r)
	case r.Method == "GET" && action == "callback":
		c.callback(w, r)
	case r.Method == "POST" && action == "signout":
		c.signOut(w, r)
	case action == "sessions" || strings.HasPrefix(action, "sessions/"):
		c.sessions(w, r, action)
	case r.Method == "POST" && action == "team":
		c.switchTeam(w, r)
	case action == "teams" || strings.HasPrefix(action, "teams/"):
		c.teams(w, r, action)
	case r.Method == "GET" && action == "session":
		secure := c.secure(r)
		res, err := c.readSession(r, true, secure)
		if err != nil {
			writeJSON(w, 502, map[string]string{"error": "inid_unavailable"})
			return
		}
		addCookies(w, res.setCookies)
		var user *User
		if res.session != nil {
			user = res.session.User
		}
		writeJSON(w, 200, map[string]any{
			"user":       user,
			"accountUrl": c.cfg.Issuer + "/account?" + url.Values{"client_id": {c.cfg.PublishableKey}}.Encode(),
		})
	default:
		writeJSON(w, 404, map[string]string{"error": "not_found"})
	}
}

func (c *Client) signIn(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	// display=embed: InID's form inside the app's own page (<inid-sign-in>)
	embed := q.Get("display") == "embed"
	// Back from Google, the frame goes on with the same sign-in (its flow cookie stays)
	if resume, ok := q["continue"]; embed && ok {
		given, _ := url.ParseQuery(resume[0])
		kept := url.Values{}
		for _, k := range []string{"request", "session", "from", "lang"} {
			if v := given.Get(k); v != "" {
				kept.Set(k, v)
			}
		}
		kept.Set("display", "embed")
		redirect(w, c.cfg.Issuer+"/oauth/authorize/continue?"+kept.Encode(), 302)
		return
	}
	f := flow{State: random(16), Nonce: random(16), Verifier: random(32), ReturnTo: safeReturn(q.Get("return_to"))}
	if embed {
		// page: where the form is, to go on there after Google
		page := q.Get("page")
		if page == "" {
			page = q.Get("return_to")
		}
		f.Embed, f.Page = true, safeReturn(page)
	}
	origin := c.origin(r)
	query := url.Values{
		"client_id":             {c.cfg.PublishableKey},
		"redirect_uri":          {origin + c.cfg.APIPath + "/callback"},
		"response_type":         {"code"},
		"scope":                 {c.cfg.Scope},
		"state":                 {f.State},
		"nonce":                 {f.Nonce},
		"code_challenge":        {challenge(f.Verifier)},
		"code_challenge_method": {"S256"},
	}
	for _, k := range []string{"ui_locales", "login_hint", "prompt", "entrance"} {
		if v := q.Get(k); v != "" {
			query.Set(k, v)
		}
	}
	// In the page, someone still clicks to go in: never signed in by just loading it
	if embed {
		query.Set("display", "embed")
		query.Set("prompt", "login")
	}
	// Right after signing out of the app, InID asks too: they chose to leave
	if _, out := parseCookies(r)[cookieOut]; out {
		query.Set("prompt", "login")
	}
	raw, _ := json.Marshal(f)
	// One cookie per sign-in (named by its state): two at once don't overwrite each other
	flowCookie := cookie(cookieFlow+"_"+f.State, b64url(raw), flowMaxAge, c.cfg.APIPath, strings.HasPrefix(origin, "https://"))
	redirect(w, c.cfg.Issuer+"/oauth/authorize?"+query.Encode(), 302, flowCookie)
}

func (c *Client) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	origin := c.origin(r)
	secure := strings.HasPrefix(origin, "https://")
	state := q.Get("state")
	flowName := cookieFlow
	if stateName.MatchString(state) {
		flowName = cookieFlow + "_" + state
	}
	clearFlow := cookie(flowName, "", 0, c.cfg.APIPath, secure)
	var f *flow
	if raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parseCookies(r)[flowName], "=")); err == nil {
		var parsed flow
		if json.Unmarshal(raw, &parsed) == nil && parsed.State != "" {
			f = &parsed
		}
	}
	// Back from Google, a sign-in that started in the app's page goes on in it: back to that
	// page, whose form opens where InID left it
	if resume, ok := q["inid_continue"]; ok && f != nil && f.Embed && state == f.State {
		page, err := url.Parse(safeReturn(f.Page))
		if err != nil {
			page = &url.URL{Path: "/"}
		}
		pq := page.Query()
		pq.Set("inid_continue", resume[0])
		page.RawQuery = pq.Encode()
		// The flow cookie stays: the same sign-in comes back here with its code
		redirect(w, page.RequestURI(), 302)
		return
	}
	// From InID's form inside the page, the whole page goes on (not just its frame)
	goTo := func(to string, cookies ...string) {
		if f != nil && f.Embed {
			leaveFrame(w, to, cookies...)
		} else {
			redirect(w, to, 302, cookies...)
		}
	}
	code := q.Get("code")
	if f == nil || code == "" || state != f.State {
		returnTo := "/"
		if f != nil {
			returnTo = safeReturn(f.ReturnTo)
		}
		goTo(returnTo, clearFlow)
		return
	}
	t, err := c.token(r.Context(), url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {origin + c.cfg.APIPath + "/callback"},
		"code_verifier": {f.Verifier},
	})
	if err != nil {
		var ie *Error
		if errors.As(err, &ie) && ie.Status < 500 {
			writeJSON(w, 400, map[string]string{"error": ie.Code})
		} else {
			writeJSON(w, 502, map[string]string{"error": "inid_unavailable"})
		}
		return
	}
	v, err := c.verifyIDToken(t.IDToken, f.Nonce, true)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": "inid_unavailable"})
		return
	}
	if v == nil || v.expired {
		writeJSON(w, 400, map[string]string{"error": "invalid_id_token"})
		return
	}
	cookies := append([]string{clearFlow}, sessionCookies(t, secure)...)
	cookies = append(cookies, cookie(cookieOut, "", 0, "/", secure))
	goTo(safeReturn(f.ReturnTo), cookies...)
}

func (c *Client) signOut(w http.ResponseWriter, r *http.Request) {
	secure := c.secure(r)
	// The sign-in ends at InID too (best effort); the person's InID stays signed in
	if refresh := parseCookies(r)[cookieRefresh]; refresh != "" {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		if res, err := c.postForm(ctx, "/oauth/revoke", url.Values{"token": {refresh}, "token_type_hint": {"refresh_token"}}); err == nil {
			res.Body.Close()
		}
		cancel()
	}
	addCookies(w, clearCookies(secure))
	addCookies(w, []string{cookie(cookieOut, "1", cookieMaxAge, "/", secure)})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// switchTeam sets the person's active team: POST team {"teamId"} (null: their own account).
// InID renews the session with it, so the new cookies (and this answer) say the team.
func (c *Client) switchTeam(w http.ResponseWriter, r *http.Request) {
	secure := c.secure(r)
	jar := parseCookies(r)
	res, err := c.readSession(r, false, secure)
	if err != nil || res.session == nil || jar[cookieRefresh] == "" {
		writeJSON(w, 401, map[string]string{"error": "not_signed_in"})
		return
	}
	var body map[string]any
	_ = json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&body)
	team := ""
	switch asked := body["teamId"].(type) {
	case nil:
	case string:
		team = asked
	default:
		writeJSON(w, 400, map[string]string{"error": "invalid_request"})
		return
	}
	t, err := c.token(r.Context(), url.Values{"grant_type": {"refresh_token"}, "refresh_token": {jar[cookieRefresh]}, "team": {team}})
	var renewed *verified
	if err == nil {
		renewed, err = c.verifyIDToken(t.IDToken, "", false)
		if err == nil && renewed == nil {
			err = &Error{Code: "invalid_id_token", Status: 400}
		}
	}
	if err != nil {
		var ie *Error
		if !errors.As(err, &ie) {
			writeJSON(w, 502, map[string]string{"error": "inid_unavailable"})
			return
		}
		// The session itself is over; anything else (a team they aren't in) leaves it as it was
		if ie.Code == "invalid_grant" {
			addCookies(w, clearCookies(secure))
			writeJSON(w, 401, map[string]string{"error": "not_signed_in"})
			return
		}
		status := 502
		if ie.Status > 0 && ie.Status < 500 {
			status = 400
		}
		writeJSON(w, status, map[string]string{"error": ie.Code})
		return
	}
	addCookies(w, sessionCookies(t, secure))
	writeJSON(w, 200, map[string]any{"user": userOf(renewed.claims)})
}

// teams forwards the person's own team calls through the app's server (InID checks what their
// team role lets them do): teams, teams/{id}, teams/{id}/members… → /v1/users/{sub}/teams…
func (c *Client) teams(w http.ResponseWriter, r *http.Request, action string) {
	res, err := c.readSession(r, false, c.secure(r))
	if err != nil || res.session == nil {
		writeJSON(w, 401, map[string]string{"error": "not_signed_in"})
		return
	}
	rest := action[len("teams"):]
	switch r.Method {
	case "GET", "POST", "PATCH", "DELETE":
	default:
		writeJSON(w, 404, map[string]string{"error": "not_found"})
		return
	}
	if !teamsRest.MatchString(rest) {
		writeJSON(w, 404, map[string]string{"error": "not_found"})
		return
	}
	var body io.Reader
	if r.Method == "POST" || r.Method == "PATCH" {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if len(raw) > 0 {
			body = bytes.NewReader(raw)
		}
	}
	target := c.cfg.Issuer + "/v1/users/" + url.PathEscape(res.session.User.ID) + "/teams" + rest
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target, body)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": "teams_unavailable"})
		return
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.SecretKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	answer, err := c.http.Do(req)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": "teams_unavailable"})
		return
	}
	defer answer.Body.Close()
	raw, _ := io.ReadAll(answer.Body)
	status := answer.StatusCode
	if status >= 500 {
		status = 502
	}
	if !json.Valid(raw) {
		writeJSON(w, status, map[string]string{"error": "teams_unavailable"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

// sessions lists the person's sessions at this app, or ends one (sessions/{id}) or all but
// this one (sessions?others=1).
func (c *Client) sessions(w http.ResponseWriter, r *http.Request, action string) {
	res, err := c.readSession(r, false, c.secure(r))
	if err != nil || res.session == nil {
		writeJSON(w, 401, map[string]string{"error": "not_signed_in"})
		return
	}
	current := res.session
	base := "/v1/users/" + url.PathEscape(current.User.ID) + "/sessions"
	sid, _ := current.Claims["sid"].(string)
	type remote struct {
		ID           string  `json:"id"`
		CreatedAt    string  `json:"createdAt"`
		LastActiveAt string  `json:"lastActiveAt"`
		Device       *string `json:"device"`
		Current      bool    `json:"current"`
	}
	list := func() ([]remote, error) {
		var body struct {
			Sessions []remote `json:"sessions"`
		}
		if err := c.appAPI(r.Context(), "GET", base, nil, &body); err != nil {
			return nil, err
		}
		return body.Sessions, nil
	}
	switch r.Method {
	case "GET":
		all, err := list()
		if err != nil {
			writeJSON(w, 502, map[string]string{"error": "sessions_unavailable"})
			return
		}
		for i := range all {
			all[i].Current = all[i].ID == sid
		}
		if all == nil {
			all = []remote{}
		}
		writeJSON(w, 200, map[string]any{"sessions": all})
	case "DELETE":
		var ending []string
		if strings.HasPrefix(action, "sessions/") {
			one, err := url.PathUnescape(action[len("sessions/"):])
			if err != nil || one == "" {
				writeJSON(w, 404, map[string]string{"error": "not_found"})
				return
			}
			ending = []string{one}
		} else if r.URL.Query().Get("others") != "" {
			all, err := list()
			if err != nil {
				writeJSON(w, 502, map[string]string{"error": "sessions_unavailable"})
				return
			}
			for _, s := range all {
				if s.ID != sid {
					ending = append(ending, s.ID)
				}
			}
		}
		for _, id := range ending {
			_ = c.appAPI(r.Context(), "DELETE", base+"/"+url.PathEscape(id), nil, nil)
		}
		writeJSON(w, 200, map[string]int{"ended": len(ending)})
	default:
		writeJSON(w, 404, map[string]string{"error": "not_found"})
	}
}
