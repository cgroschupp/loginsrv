package oauth2

import (
	"crypto/tls"
	"errors"
	. "github.com/stretchr/testify/assert"
	"github.com/tarent/loginsrv/model"
	"golang.org/x/oauth2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func Test_Manager_Positive_Flow(t *testing.T) {
	var startFlowCalled, authenticateCalled, getUserInfoCalled bool
	var startFlowReceivedConfig, authenticateReceivedConfig Config
	expectedToken := oauth2.Token{AccessToken: "the-access-token"}

	exampleProvider := Provider{
		Name: "example",
		GetEndpoint: func(config *Config) oauth2.Endpoint {
			return oauth2.Endpoint{
				AuthURL:  "https://example.com/login/oauth/authorize",
				TokenURL: "https://example.com/login/oauth/access_token",
			}
		},
		GetUserInfo: func(token *oauth2.Token, config *Config) (model.UserInfo, string, error) {
			getUserInfoCalled = true
			Equal(t, token, &expectedToken)
			return model.UserInfo{
				Sub: "the-username",
			}, "", nil
		},
	}
	RegisterProvider(exampleProvider)
	defer UnRegisterProvider(exampleProvider.Name)

	expectedConfig := Config{
		Provider: exampleProvider,
		Config: oauth2.Config{
			ClientID:     "client42",
			ClientSecret: "secret",
			Endpoint: oauth2.Endpoint{
				AuthURL:  exampleProvider.GetEndpoint(nil).AuthURL,
				TokenURL: exampleProvider.GetEndpoint(nil).TokenURL,
			},
			RedirectURL: "http://localhost",
			Scopes:      []string{"email", "other"},
		},
	}

	m := NewManager()
	m.AddConfig(exampleProvider.Name, map[string]string{
		"client_id":     expectedConfig.Config.ClientID,
		"client_secret": expectedConfig.Config.ClientSecret,
		"scope":         strings.Join(expectedConfig.Config.Scopes, " "),
		"redirect_uri":  expectedConfig.Config.RedirectURL,
	})

	m.startFlow = func(cfg Config, w http.ResponseWriter) {
		startFlowCalled = true
		startFlowReceivedConfig = cfg
	}

	m.authenticate = func(cfg Config, r *http.Request) (*oauth2.Token, error) {
		authenticateCalled = true
		authenticateReceivedConfig = cfg
		return &expectedToken, nil
	}

	// start flow
	r, _ := http.NewRequest("GET", "http://example.com/login/"+exampleProvider.Name, nil)

	startedFlow, authenticated, userInfo, err := m.Handle(httptest.NewRecorder(), r)
	NoError(t, err)
	True(t, startedFlow)
	False(t, authenticated)
	Equal(t, model.UserInfo{}, userInfo)

	True(t, startFlowCalled)
	False(t, authenticateCalled)

	assertEqualConfig(t, expectedConfig, startFlowReceivedConfig)

	// callback
	r, _ = http.NewRequest("GET", "http://example.com/login/"+exampleProvider.Name+"?code=xyz", nil)

	startedFlow, authenticated, userInfo, err = m.Handle(httptest.NewRecorder(), r)
	NoError(t, err)
	False(t, startedFlow)
	True(t, authenticated)
	Equal(t, model.UserInfo{Sub: "the-username"}, userInfo)
	True(t, authenticateCalled)
	assertEqualConfig(t, expectedConfig, authenticateReceivedConfig)

	True(t, getUserInfoCalled)
}

func Test_Manager_NoAauthOnWrongCode(t *testing.T) {
	var authenticateCalled, getUserInfoCalled bool

	exampleProvider := Provider{
		Name: "example",
		GetEndpoint: func(config *Config) oauth2.Endpoint {
			return oauth2.Endpoint{
				AuthURL:  "https://example.com/login/oauth/authorize",
				TokenURL: "https://example.com/login/oauth/access_token",
			}
		},
		GetUserInfo: func(token *oauth2.Token, config *Config) (model.UserInfo, string, error) {
			getUserInfoCalled = true
			return model.UserInfo{}, "", nil
		},
	}
	RegisterProvider(exampleProvider)
	defer UnRegisterProvider(exampleProvider.Name)

	m := NewManager()
	m.AddConfig(exampleProvider.Name, map[string]string{
		"client_id":     "foo",
		"client_secret": "bar",
	})

	m.authenticate = func(cfg Config, r *http.Request) (*oauth2.Token, error) {
		authenticateCalled = true
		return &oauth2.Token{}, errors.New("code not valid")
	}

	// callback
	r, _ := http.NewRequest("GET", "http://example.com/login/"+exampleProvider.Name+"?code=xyz", nil)

	startedFlow, authenticated, userInfo, err := m.Handle(httptest.NewRecorder(), r)
	EqualError(t, err, "code not valid")
	False(t, startedFlow)
	False(t, authenticated)
	Equal(t, model.UserInfo{}, userInfo)
	True(t, authenticateCalled)
	False(t, getUserInfoCalled)
}

func Test_Manager_getConfig_ErrorCase(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://example.com/login", nil)

	m := NewManager()
	m.AddConfig("github", map[string]string{
		"client_id":     "foo",
		"client_secret": "bar",
	})

	_, err := m.GetConfigFromRequest(r)
	EqualError(t, err, "no oauth configuration for login")
}

func Test_Manager_AddConfig_ErrorCases(t *testing.T) {
	m := NewManager()

	NoError(t,
		m.AddConfig("github", map[string]string{
			"client_id":     "foo",
			"client_secret": "bar",
		}))

	EqualError(t,
		m.AddConfig("FOOOO", map[string]string{
			"client_id":     "foo",
			"client_secret": "bar",
		}),
		"no provider for name FOOOO",
	)

	EqualError(t,
		m.AddConfig("github", map[string]string{
			"client_secret": "bar",
		}),
		"missing parameter client_id",
	)

	EqualError(t,
		m.AddConfig("github", map[string]string{
			"client_id": "foo",
		}),
		"missing parameter client_secret",
	)

}

func Test_Manager_redirectUriFromRequest(t *testing.T) {
	tests := []struct {
		url      string
		tls      bool
		header   http.Header
		expected string
	}{
		{
			"http://example.com/login/github",
			false,
			http.Header{},
			"http://example.com/login/github",
		},
		{
			"http://localhost/login/github",
			false,
			http.Header{
				"X-Forwarded-Host": {"example.com"},
			},
			"http://example.com/login/github",
		},
		{
			"http://localhost/login/github",
			true,
			http.Header{
				"X-Forwarded-Host": {"example.com"},
			},
			"https://example.com/login/github",
		},
		{
			"http://localhost/login/github",
			false,
			http.Header{
				"X-Forwarded-Host":  {"example.com"},
				"X-Forwarded-Proto": {"https"},
			},
			"https://example.com/login/github",
		},
	}
	for _, test := range tests {
		t.Run(test.url, func(t *testing.T) {
			r, _ := http.NewRequest("GET", test.url, nil)
			r.Header = test.header
			if test.tls {
				r.TLS = &tls.ConnectionState{}
			}
			uri := redirectURIFromRequest(r)
			Equal(t, test.expected, uri)
		})
	}
}

func Test_Manager_RedirectURI_Generation(t *testing.T) {
	var startFlowReceivedConfig Config

	m := NewManager()
	m.AddConfig("github", map[string]string{
		"client_id":     "foo",
		"client_secret": "bar",
		"scope":         "bazz",
	})

	m.startFlow = func(cfg Config, w http.ResponseWriter) {
		startFlowReceivedConfig = cfg
	}

	callURL := "http://example.com/login/github"
	r, _ := http.NewRequest("GET", callURL, nil)

	_, _, _, err := m.Handle(httptest.NewRecorder(), r)
	NoError(t, err)
	Equal(t, callURL, startFlowReceivedConfig.Config.RedirectURL)
}

func assertEqualConfig(t *testing.T, c1, c2 Config) {
	Equal(t, c1.Config.Endpoint.AuthURL, c2.Config.Endpoint.AuthURL)
	Equal(t, c1.Config.ClientID, c2.Config.ClientID)
	Equal(t, c1.Config.ClientSecret, c2.Config.ClientSecret)
	Equal(t, c1.Config.Scopes, c2.Config.Scopes)
	Equal(t, c1.Config.RedirectURL, c2.Config.RedirectURL)
	Equal(t, c1.Config.Endpoint.TokenURL, c2.Config.Endpoint.TokenURL)
	Equal(t, c1.Provider.Name, c2.Provider.Name)
}
