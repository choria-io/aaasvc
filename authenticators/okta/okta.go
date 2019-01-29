package okta

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/okta/okta-sdk-golang/okta"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/choria-io/aaasvc/api/gen/models"
	"github.com/choria-io/aaasvc/authenticators"
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

// New creates a new Okta authenticator
func New(c *AuthenticatorConfig, log *logrus.Entry, site string) (a *Authenticator, err error) {
	validity, err := time.ParseDuration(c.TokenValidity)
	if err != nil {
		return nil, errors.Wrap(err, "invalid token validity")
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

	token := jwt.NewWithClaims(jwt.GetSigningMethod("RS512"), jwt.MapClaims{
		"exp":      time.Now().UTC().Add(a.validity).Unix(),
		"nbf":      time.Now().UTC().Add(-1 * time.Minute).Unix(),
		"iat":      time.Now().UTC(),
		"iss":      "Choria Okta Authenticator",
		"sub":      fmt.Sprintf("okta=%s", req.Username),
		"agents":   allowedActions,
		"callerid": fmt.Sprintf("okta=%s", req.Username),
	})

	signKey, err := a.signKey()
	if err != nil {
		resp.Error = fmt.Sprintf("Could not load signing key %s: %s", a.c.SigningKey, err)
		return
	}

	signed, err := token.SignedString(signKey)
	if err != nil {
		resp.Error = fmt.Sprintf("Could not sign JWT: %s", err)
		return
	}

	resp.Token = signed

	return resp
}

func (a *Authenticator) signKey() (*rsa.PrivateKey, error) {
	pkeyBytes, err := ioutil.ReadFile(a.c.SigningKey)
	if err != nil {
		return nil, errors.Wrap(err, "could not read")
	}

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(pkeyBytes)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse")
	}

	return signKey, nil
}

func (a *Authenticator) login(user string, password string) (resp *tokenResponse, ok bool, err error) {
	body := url.Values{}
	body.Set("grant_type", "password")
	body.Set("scope", "openid")
	body.Set("username", user)
	body.Set("password", password)

	post, err := http.NewRequest("POST", fmt.Sprintf("%s/oauth2/default/v1/token", a.c.EndPoint), bytes.NewBufferString(body.Encode()))
	if err != nil {
		return nil, false, errors.Wrap(err, "could not create request")
	}

	post.Header.Set("accept", "application/json")
	post.Header.Set("content-type", "application/x-www-form-urlencoded")
	post.SetBasicAuth(a.c.ClientID, a.c.ClientSecret)

	client := &http.Client{}
	postresp, err := client.Do(post)
	if err != nil {
		return nil, false, errors.Wrap(err, "could not create POST request")
	}
	defer postresp.Body.Close()

	respbody, err := ioutil.ReadAll(postresp.Body)
	if err != nil {
		return nil, false, errors.Wrap(err, "could not parse okta response")
	}

	authresp := &tokenResponse{}
	err = json.Unmarshal(respbody, authresp)
	if err != nil {
		return nil, false, errors.Wrap(err, "could not parse response")
	}

	if authresp.Error != "" {
		return nil, false, errors.Errorf("login failed: %s", authresp.ErrorDescription)
	}

	return authresp, true, nil
}

func (a *Authenticator) userGroups(userid string) (groups []string, err error) {
	config := okta.NewConfig().WithOrgUrl(a.c.EndPoint).WithToken(a.c.APIToken)
	client := okta.NewClient(config, nil, nil)

	user, _, err := client.User.GetUser(userid, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "could not fetch user %s", userid)
	}

	ogroups, _, err := client.User.ListUserGroups(user.Id, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "could not fetch groups for user %s", userid)
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
