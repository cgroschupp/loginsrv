package oauth2

import (
	"encoding/json"
	"fmt"
	"github.com/tarent/loginsrv/model"
	"io/ioutil"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

var githubAPI = "https://api.github.com"

func init() {
	RegisterProvider(providerGithub)
}

// GithubUser is used for parsing the github response
type GithubUser struct {
	Login     string `json:"login,omitempty"`
	AvatarURL string `json:"avatar_url,omitempty"`
	Name      string `json:"name,omitempty"`
	Email     string `json:"email,omitempty"`
}

var providerGithub = Provider{
	Name: "github",
	GetEndpoint: func(config *Config, opts map[string]string) oauth2.Endpoint {
		return github.Endpoint
	},
	GetUserInfo: func(token *oauth2.Token, config *Config) (model.UserInfo, string, error) {
		gu := GithubUser{}
		url := fmt.Sprintf("%v/user?access_token=%v", githubAPI, token.AccessToken)
		resp, err := http.Get(url)
		if err != nil {
			return model.UserInfo{}, "", err
		}

		if !strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
			return model.UserInfo{}, "", fmt.Errorf("wrong content-type on github get user info: %v", resp.Header.Get("Content-Type"))
		}

		if resp.StatusCode != 200 {
			return model.UserInfo{}, "", fmt.Errorf("got http status %v on github get user info", resp.StatusCode)
		}

		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return model.UserInfo{}, "", fmt.Errorf("error reading github get user info: %v", err)
		}

		err = json.Unmarshal(b, &gu)
		if err != nil {
			return model.UserInfo{}, "", fmt.Errorf("error parsing github get user info: %v", err)
		}

		return model.UserInfo{
			Sub:     gu.Login,
			Picture: gu.AvatarURL,
			Name:    gu.Name,
			Email:   gu.Email,
			Origin:  "github",
		}, string(b), nil
	},
}
