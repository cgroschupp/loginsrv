package oauth2

import (
	"github.com/tarent/loginsrv/model"
	"golang.org/x/oauth2"
)

// Provider is the description of an oauth provider adapter
type Provider struct {
	// The name to access the provider in the configuration
	Name string

	// GetUserInfo is a provider specific Implementation
	// for fetching the user information.
	// Possible keys in the returned map are:
	// username, email, name
	GetUserInfo func(token *oauth2.Token, config *Config) (u model.UserInfo, rawUserJson string, err error)
	GetEndpoint func(config *Config, opts map[string]string) (endpoint oauth2.Endpoint)
}

var provider = map[string]Provider{}

// RegisterProvider an Oauth provider
func RegisterProvider(p Provider) {
	provider[p.Name] = p
}

// UnRegisterProvider removes a provider
func UnRegisterProvider(name string) {
	delete(provider, name)
}

// GetProvider returns a provider
func GetProvider(providerName string) (Provider, bool) {
	p, exist := provider[providerName]
	return p, exist
}

// ProviderList returns the names of all registered provider
func ProviderList() []string {
	list := make([]string, 0, len(provider))
	for k := range provider {
		list = append(list, k)
	}
	return list
}
