# InID for Go

Sign-in with [InID](https://inid.co) for Go servers. People sign in with their phone (a code by WhatsApp or SMS), a passkey (Face ID, fingerprint, Windows Hello or the device PIN) or Google, without passwords; your server knows who they are, their role and their permissions.

Standard library only. Works with `net/http`, chi, gorilla/mux, echo (via `echo.WrapMiddleware`) and anything else that takes an `http.Handler`.

```bash
go get github.com/inidhq/inid-go
```

Set your keys from InID's panel (Settings → Keys):

```bash
INID_PUBLISHABLE_KEY=pk_test_...
INID_SECRET_KEY=sk_test_...
INID_WEBHOOK_SECRET=whsec_...   # only to verify webhooks
INID_APP_URL=https://app.example.com   # behind a proxy that hides the scheme or host
```

## net/http

```go
package main

import (
	"fmt"
	"log"
	"net/http"

	inid "github.com/inidhq/inid-go"
)

func main() {
	client, err := inid.NewFromEnv()
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		auth := inid.FromContext(r.Context())
		fmt.Fprintf(w, "Hola, %s", *auth.User.Name)
	})

	handler := client.Middleware(mux, inid.Protect(
		inid.Path("/dashboard"),                                   // signed in
		inid.Rule{Path: "/admin", Role: "admin"},                  // signed in with a role
		inid.Rule{Path: "/team", Entrance: "team"},                // through an entrance
		inid.Regex(`^/reports/\d+$`),                              // a pattern
	))
	log.Fatal(http.ListenAndServe(":3000", handler))
}
```

The middleware answers InID's routes under `/api/inid` (sign in, callback, sign out, session, sessions), renews the session before it ends, sends whoever isn't signed in from a protected path to sign in (and back), and answers `403` to someone signed in without the role or permission a rule asks for.

`inid.FromContext(ctx)` gives an `*inid.Auth`: `IsSignedIn`, `UserID`, `User` (`ID`, `FirstName`, `LastName`, `Name`, `Email`, `EmailVerified`, `Phone`, `Roles`, `Permissions`, `PublicMetadata`), `Session` (with the token's `Claims`) and `Has(inid.Check{Role: "admin"})` / `Has(inid.Check{Permission: "invoices:read"})`.

## chi

```go
r := chi.NewRouter()
r.Use(client.Gate(inid.Protect(inid.Path("/dashboard"))))
r.Get("/dashboard", func(w http.ResponseWriter, r *http.Request) {
	user := inid.FromContext(r.Context()).User
	fmt.Fprintf(w, "Hola, %s", user.ID)
})
```

`client.Gate(opts...)` is the middleware as `func(http.Handler) http.Handler`. To mount the routes yourself, use `inid.SkipRoutes()` and `mux.Handle("/api/inid/", client.Handler())` (without stripping the prefix).

## Components

The sign-in form and the user button are web components from [`@inid/js`](https://www.npmjs.com/package/@inid/js); they talk to the routes above:

```html
<script src="https://cdn.jsdelivr.net/npm/@inid/js@0.1/dist/inid.global.js"></script>
<inid-sign-in app-name="Mi App"></inid-sign-in>
```

## Native apps

An iOS or Android app sends its ID token to your backend as `Authorization: Bearer <id_token>`:

```go
session, err := client.VerifyBearer(r.Header.Get("Authorization"))
if err != nil {
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return
}
fmt.Println(session.User.ID)
```

## Webhooks

Pass the raw body, as received:

```go
body, _ := io.ReadAll(r.Body)
event, err := client.VerifyWebhook(body, r.Header.Get("InID-Signature"))
if err != nil {
	http.Error(w, "invalid signature", http.StatusBadRequest)
	return
}
switch event.Type {
case "user.deleted":
	// event.Sub
case "session.ended":
	// event.Sub, event.Sid
}
```

Without a client: `inid.VerifyWebhook(secret, body, header, time.Now())`.

## The app API

With your secret key:

```go
user, err := client.GetUser(ctx, sub)
err = client.SetRole(ctx, sub, "admin")                 // "" for the default role
err = client.SetMetadata(ctx, sub, inid.Metadata{Public: map[string]any{"plan": "pro"}})
roles, err := client.Roles(ctx)
_, err = client.Invite(ctx, inid.Invitation{Email: "ana@example.com", Role: "staff"})
```

Errors from InID are `*inid.Error` with `Code` (`user_not_found`, `unknown_role`…) and `Status`.

## Configuration

`inid.New(inid.Config{...})` takes `PublishableKey`, `SecretKey`, `Issuer` (default `https://id.inid.co`), `AppURL`, `APIPath` (default `/api/inid`), `Scope` (default `openid profile email phone`), `WebhookSecret` and `HTTPClient`. Missing or malformed keys fail there, at startup.

## License

MIT
