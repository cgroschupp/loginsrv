package oauth2

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"golang.org/x/oauth2"
	"context"
	oidc "github.com/coreos/go-oidc"
	"fmt"

	. "github.com/stretchr/testify/assert"
)

func Test_Oidc_getUserInfo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("\n%v\n", r)
		Equal(t, "secret", r.FormValue("access_token"))
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Write([]byte(googleTestUserResponse))
	}))
	defer server.Close()




	config := Config{
		Config: oauth2.Config{
			ClientID:     "client42",
			ClientSecret: "secret",
			Endpoint: oauth2.Endpoint{
				AuthURL:  server.URL,
				TokenURL: server.URL,
			},
			RedirectURL: "http://localhost",
			Scopes:      []string{"email", "other"},
		},
	}

	ctx := context.Background()
	config.OIDCProvider, _ = oidc.NewProvider(ctx, server.URL)


	token := oauth2.Token{
		AccessToken: "secret",
	}

	u, rawJSON, err := providerOidc.GetUserInfo(&token, &config)
	NoError(t, err)
	Equal(t, "test@gmail.com", u.Sub)
	Equal(t, "test@gmail.com", u.Email)
	Equal(t, "https://lh3.googleusercontent.com/X/X/X/X/photo.jpg", u.Picture)
	Equal(t, "Testy Test", u.Name)
	Equal(t, "gmail.com", u.Domain)
	Equal(t, googleTestUserResponse, rawJSON)
}
