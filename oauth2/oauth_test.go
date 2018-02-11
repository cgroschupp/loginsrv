package oauth2

import (
	"fmt"
	. "github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

var testConfig = Config{
	Config: oauth2.Config{
		ClientID:     "client42",
		ClientSecret: "secret",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "http://auth-provider/auth",
			TokenURL: "http://auth-provider/token",
		},
		RedirectURL: "http://localhost/callback",
		Scopes:      []string{"email", "other"},
	},
}

func Test_StartFlow(t *testing.T) {
	resp := httptest.NewRecorder()
	StartFlow(testConfig, resp)

	Equal(t, http.StatusFound, resp.Code)

	// assert that we received a state cookie
	cHeader := strings.Split(resp.Header().Get("Set-Cookie"), ";")[0]
	Equal(t, stateCookieName, strings.Split(cHeader, "=")[0])
	state := strings.Split(cHeader, "=")[1]

	expectedLocation := fmt.Sprintf("%v?client_id=%v&redirect_uri=%v&response_type=code&scope=%v&state=%v",
		testConfig.Config.Endpoint.AuthURL,
		testConfig.Config.ClientID,
		url.QueryEscape(testConfig.Config.RedirectURL),
		"email+other",
		state,
	)

	Equal(t, expectedLocation, resp.Header().Get("Location"))
}

func Test_Authenticate(t *testing.T) {
	// mock a server for token exchange
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Equal(t, "POST", r.Method)
		Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
		//Equal(t, "application/json", r.Header.Get("Accept"))

		body, _ := ioutil.ReadAll(r.Body)
		Equal(t, "code=theCode&grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback", string(body))
		Equal(t, "Basic Y2xpZW50NDI6c2VjcmV0", r.Header.Get("Authorization"))

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"e72e16c7e42f292c6912e7710c838347ae178b4a", "scope":"repo gist", "token_type":"bearer"}`))
	}))
	defer server.Close()

	testConfigCopy := testConfig
	testConfigCopy.Config.Endpoint.TokenURL = server.URL

	request, _ := http.NewRequest("GET", testConfig.Config.RedirectURL, nil)
	request.Header.Set("Cookie", "oauthState=theState")
	request.URL, _ = url.Parse("http://localhost/callback?code=theCode&state=theState")

	tokenInfo, err := Authenticate(testConfigCopy, request)

	NoError(t, err)
	Equal(t, "e72e16c7e42f292c6912e7710c838347ae178b4a", tokenInfo.AccessToken)
	Equal(t, "repo gist", tokenInfo.Extra("scope"))
	Equal(t, "bearer", tokenInfo.TokenType)
}

func Test_Authenticate_CodeExchangeError(t *testing.T) {
	var testReturnCode int
	testResponseJSON := `{"error":"bad_verification_code","error_description":"The code passed is incorrect or expired.","error_uri":"https://developer.github.com/v3/oauth/#bad-verification-code"}`
	// mock a server for token exchange
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(testReturnCode)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(testResponseJSON))
	}))
	defer server.Close()

	testConfigCopy := testConfig
	testConfigCopy.Config.Endpoint.TokenURL = server.URL

	request, _ := http.NewRequest("GET", testConfig.Config.RedirectURL, nil)
	request.Header.Set("Cookie", "oauthState=theState")
	request.URL, _ = url.Parse("http://localhost/callback?code=theCode&state=theState")

	testReturnCode = 500
	tokenInfo, err := Authenticate(testConfigCopy, request)
	Error(t, err)
	Equal(t, false, tokenInfo.Valid())

	testReturnCode = 200
	tokenInfo, err = Authenticate(testConfigCopy, request)
	Equal(t, false, tokenInfo.Valid())

	testReturnCode = 200
	testResponseJSON = `{"foo": "bar"}`
	tokenInfo, err = Authenticate(testConfigCopy, request)
	Equal(t, false, tokenInfo.Valid())
}

func Test_Authentication_ProviderError(t *testing.T) {
	request, _ := http.NewRequest("GET", testConfig.Config.RedirectURL, nil)
	request.URL, _ = url.Parse("http://localhost/callback?error=provider_login_error")

	_, err := Authenticate(testConfig, request)

	Error(t, err)
	Equal(t, "error: provider_login_error", err.Error())
}

func Test_Authentication_StateError(t *testing.T) {
	request, _ := http.NewRequest("GET", testConfig.Config.RedirectURL, nil)
	request.Header.Set("Cookie", "oauthState=XXXXXXX")
	request.URL, _ = url.Parse("http://localhost/callback?code=theCode&state=theState")

	_, err := Authenticate(testConfig, request)

	Error(t, err)
	Equal(t, "error: oauth state param could not be verified", err.Error())
}

func Test_Authentication_NoCodeError(t *testing.T) {
	request, _ := http.NewRequest("GET", testConfig.Config.RedirectURL, nil)
	request.Header.Set("Cookie", "oauthState=theState")
	request.URL, _ = url.Parse("http://localhost/callback?state=theState")

	_, err := Authenticate(testConfig, request)

	Error(t, err)
	Equal(t, "error: no auth code provided", err.Error())
}

func Test_Authentication_Provider500(t *testing.T) {
	// mock a server for token exchange
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer server.Close()

	testConfigCopy := testConfig
	testConfigCopy.Config.Endpoint.TokenURL = server.URL

	request, _ := http.NewRequest("GET", testConfig.Config.RedirectURL, nil)
	request.Header.Set("Cookie", "oauthState=theState")
	request.URL, _ = url.Parse("http://localhost/callback?code=theCode&state=theState")

	_, err := Authenticate(testConfigCopy, request)

	Error(t, err)
	Equal(t, "oauth2: cannot fetch token: 500 Internal Server Error\nResponse: ", err.Error())
}

func Test_Authentication_ProviderNetworkError(t *testing.T) {

	testConfigCopy := testConfig
	testConfigCopy.Config.Endpoint.TokenURL = "http://localhost:12345678"

	request, _ := http.NewRequest("GET", testConfig.Config.RedirectURL, nil)
	request.Header.Set("Cookie", "oauthState=theState")
	request.URL, _ = url.Parse("http://localhost/callback?code=theCode&state=theState")

	_, err := Authenticate(testConfigCopy, request)

	Error(t, err)
	Contains(t, err.Error(), "invalid port")
}

func Test_Authentication_TokenParseError(t *testing.T) {
	// mock a server for token exchange
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_t`))

	}))
	defer server.Close()

	testConfigCopy := testConfig
	testConfigCopy.Config.Endpoint.TokenURL = server.URL

	request, _ := http.NewRequest("GET", testConfig.Config.RedirectURL, nil)
	request.Header.Set("Cookie", "oauthState=theState")
	request.URL, _ = url.Parse("http://localhost/callback?code=theCode&state=theState")

	token, _ := Authenticate(testConfigCopy, request)

	Equal(t, false, token.Valid())
}
