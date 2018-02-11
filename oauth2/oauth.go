package oauth2

import (
	"context"
	"fmt"
	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
	"math/rand"
	"net/http"
	"time"
)

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
}

// Config describes a typical 3-legged OAuth2 flow, with both the
// client application information and the server's endpoint URLs.
type Config struct {
	// The oauth provider
	Provider     Provider
	Config       oauth2.Config
	OIDCProvider *oidc.Provider
}

// JSONError represents an oauth error response in json form.
type JSONError struct {
	Error string `json:"error"`
}

const stateCookieName = "oauthState"
const defaultTimeout = 5 * time.Second

// StartFlow by redirecting the user to the login provider.
// A state parameter to protect against cross-site request forgery attacks is randomly generated and stored in a cookie
func StartFlow(cfg Config, w http.ResponseWriter) {
	// set and store the state param
	state := randStringBytes(15)
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		MaxAge:   60 * 10, // 10 minutes
		Value:    state,
		HttpOnly: true,
	})

	w.Header().Set("Location", cfg.Config.AuthCodeURL(state))
	w.WriteHeader(http.StatusFound)
}

// Authenticate after coming back from the oauth flow.
// Verify the state parameter againt the state cookie from the request.
func Authenticate(cfg Config, r *http.Request) (*oauth2.Token, error) {
	if r.FormValue("error") != "" {
		return &oauth2.Token{}, fmt.Errorf("error: %v", r.FormValue("error"))
	}

	state := r.FormValue("state")
	stateCookie, err := r.Cookie(stateCookieName)
	if err != nil || stateCookie.Value != state {
		return &oauth2.Token{}, fmt.Errorf("error: oauth state param could not be verified")
	}

	code := r.FormValue("code")
	if code == "" {
		return &oauth2.Token{}, fmt.Errorf("error: no auth code provided")
	}

	ctx := context.Background()
	return cfg.Config.Exchange(ctx, code)

}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}
