package oauth2

import (
	"context"
	"fmt"
	oidc "github.com/coreos/go-oidc"
	"github.com/tarent/loginsrv/model"

	"golang.org/x/oauth2"
)

func init() {
	RegisterProvider(providerOidc)
}

var providerOidc = Provider{
	Name: "oidc",
	GetEndpoint: func(config *Config) oauth2.Endpoint {
		return config.OIDCProvider.Endpoint()
	},
	GetUserInfo: func(token *oauth2.Token, config *Config) (model.UserInfo, string, error) {
		ctx := context.Background()

		verifier := config.OIDCProvider.Verifier(&oidc.Config{ClientID: config.Config.ClientID})
		rawIDToken, exists := token.Extra("id_token").(string)

		if !exists {
			return model.UserInfo{}, "", fmt.Errorf("unable to extract id_token")
		}

		idToken, err := verifier.Verify(ctx, rawIDToken)

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
