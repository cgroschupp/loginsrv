package oauth2

import (
	"context"
	"fmt"
	oidc "github.com/coreos/go-oidc"
	"github.com/tarent/loginsrv/model"
)

func init() {
	RegisterProvider(providerOidc)
}

var providerOidc = Provider{
	Name:     "oidc",
	AuthURL:  "https://oidc.doa.otc.hlg.de/auth",
	TokenURL: "https://oidc.doa.otc.hlg.de/token",
	GetUserInfo: func(token TokenInfo) (model.UserInfo, string, error) {
		ctx := context.Background()

		keySet := oidc.NewRemoteKeySet(ctx, "https://oidc.doa.otc.hlg.de/keys")
		config := oidc.Config{
			ClientID: "example-app",
		}

		verifier := oidc.NewVerifier("https://oidc.doa.otc.hlg.de", keySet, &config)
		idToken, err := verifier.Verify(ctx, token.IDToken)

		if err != nil {
			return model.UserInfo{}, "", fmt.Errorf("unable to verify id_token: %s", err)
		}

		var claims struct {
			Email    string   `json:"email"`
			Verified bool     `json:"email_verified"`
			Groups   []string `json:"groups"`
		}
		if err := idToken.Claims(&claims); err != nil {
			return model.UserInfo{}, "", fmt.Errorf("unable to parse claim: %s", err)
		}

		return model.UserInfo{
			Sub:     "me",
			Picture: "",
			Name:    "me",
			Email:   claims.Email,
			Origin:  "oidc",
		}, string(""), nil
	},
}
