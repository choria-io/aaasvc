package okta

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/choria-io/aaasvc/api/gen/models"
	"github.com/choria-io/aaasvc/authenticators"
	"github.com/choria-io/go-choria/tokens"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

// AuthenticatorConfig configures the okta authenticator
type AuthenticatorConfig struct {
	ClientID      string              `json:"client_id"`
	ClientSecret  string              `json:"client_secret"`
	APIToken      string              `json:"api_token"`
	EndPoint      string              `json:"endpoint"`
	TokenValidity string              `json:"validity"`
	SigningKey    string              `json:"signing_key"`
	ACLs          map[string][]string `json:"acls"`
}

// Authenticator provides authorization using the Okta SaaS
type Authenticator struct {
	c        *AuthenticatorConfig
	validity time.Duration
	site     string
	log      *logrus.Entry
}

type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	Scope            string `json:"scope"`
	RefreshToken     string `json:"refresh_token"`
	IDToken          string `json:"id_token"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

const issuer = "Choria Okta Authenticator"

// New creates a new Okta authenticator
func New(c *AuthenticatorConfig, log *logrus.Entry, site string) (a *Authenticator, err error) {
	validity, err := time.ParseDuration(c.TokenValidity)
	if err != nil {
		return nil, fmt.Errorf("invalid token validity: %s", err)
	}

	a = &Authenticator{
		c:        c,
		validity: validity,
		site:     site,
		log:      log.WithField("authenticator", "okta"),
	}

	return a, nil
}

// Login logs someone in using Okta
func (a *Authenticator) Login(req *models.LoginRequest) (resp *models.LoginResponse) {
	timer := authenticators.ProcessTime.WithLabelValues(a.site, "okta")
	obs := prometheus.NewTimer(timer)
	defer obs.ObserveDuration()

	resp = a.processLogin(req)
	if resp.Error != "" {
		a.log.Warnf("Could not log in %s: %s", req.Username, resp.Error)
		authenticators.ErrCtr.WithLabelValues(a.site, "okta").Inc()
		return resp
	}

	a.log.Infof("Logged in %s", req.Username)

	return resp
}

func (a *Authenticator) processLogin(req *models.LoginRequest) (resp *models.LoginResponse) {
	resp = &models.LoginResponse{}

	_, _, err := a.login(req.Username, req.Password)
	if err != nil {
		resp.Error = fmt.Sprintf("Login Failed: %s", err)
		return
	}

	groups, err := a.userGroups(req.Username)
	if err != nil {
		resp.Error = fmt.Sprintf("Login Failed: %s", err)
		return
	}

	allowedActions := []string{}
	for _, group := range groups {
		acls, ok := a.c.ACLs[group]
		if ok {
			for _, acl := range acls {
				if !stringSliceHas(allowedActions, acl) {
					allowedActions = append(allowedActions, acl)
				}
			}
		}
	}

	cid := fmt.Sprintf("okta=%s", req.Username)
	claims, err := tokens.NewClientIDClaims(cid, allowedActions, "", nil, "", issuer, a.validity, nil)
	if err != nil {
		a.log.Warnf("Creating claims for user %s failed: %s", req.Username, err)
		resp.Error = "Login failed"
		return
	}

	signed, err := tokens.SignTokenWithKeyFile(claims, a.c.SigningKey)
	if err != nil {
		resp.Error = fmt.Sprintf("Could not sign JWT: %s", err)
		return
	}

	resp.Token = signed

	return resp
}

func (a *Authenticator) login(user string, password string) (resp *tokenResponse, ok bool, err error) {
	body := url.Values{}
	body.Set("grant_type", "password")
	body.Set("scope", "openid")
	body.Set("username", user)
	body.Set("password", password)

	post, err := http.NewRequest("POST", fmt.Sprintf("%s/oauth2/default/v1/token", a.c.EndPoint), bytes.NewBufferString(body.Encode()))
	if err != nil {
		return nil, false, fmt.Errorf("could not create request: %s", err)
	}

	post.Header.Set("accept", "application/json")
	post.Header.Set("content-type", "application/x-www-form-urlencoded")
	post.SetBasicAuth(a.c.ClientID, a.c.ClientSecret)

	client := &http.Client{}
	postresp, err := client.Do(post)
	if err != nil {
		return nil, false, fmt.Errorf("could not create POST request: %s", err)
	}
	defer postresp.Body.Close()

	respbody, err := ioutil.ReadAll(postresp.Body)
	if err != nil {
		return nil, false, fmt.Errorf("could not parse okta response: %s", err)
	}

	authresp := &tokenResponse{}
	err = json.Unmarshal(respbody, authresp)
	if err != nil {
		return nil, false, fmt.Errorf("could not parse response: %s", err)
	}

	if authresp.Error != "" {
		return nil, false, fmt.Errorf("login failed: %s", authresp.ErrorDescription)
	}

	return authresp, true, nil
}

func (a *Authenticator) userGroups(userid string) (groups []string, err error) {
	ctx, client, err := okta.NewClient(context.Background(), okta.WithOrgUrl(a.c.EndPoint), okta.WithToken(a.c.APIToken))
	if err != nil {
		return nil, err
	}

	user, _, err := client.User.GetUser(ctx, userid)
	if err != nil {
		return nil, fmt.Errorf("could not fetch user %s: %s", userid, err)
	}

	ogroups, _, err := client.User.ListUserGroups(ctx, user.Id)
	if err != nil {
		return nil, fmt.Errorf("could not fetch groups for user %s: %s", userid, err)
	}

	groups = []string{}
	for _, grp := range ogroups {
		groups = append(groups, grp.Profile.Name)
	}

	return groups, nil
}

func stringSliceHas(hs []string, n string) bool {
	for _, item := range hs {
		if item == n {
			return true
		}
	}

	return false
}
