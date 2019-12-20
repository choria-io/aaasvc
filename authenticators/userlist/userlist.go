// Package userlist provide a static configuration based authentication system
//
// Each user has a set of ACLs that are applied to the generated token, ACL strings
// have to comply with the signer you choose, refer to signer documentation for
// details.
package userlist

import (
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/choria-io/aaasvc/api/gen/models"
	"github.com/choria-io/aaasvc/authenticators"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

// AuthenticatorConfig configures the user/pass authenticator
type AuthenticatorConfig struct {
	Users         []*User
	TokenValidity string `json:"validity"`
	SigningKey    string `json:"signing_key"`
}

// Authenticator is a authenticator with a basic fixed list of users and bcrypt encrypted passwords
type Authenticator struct {
	c        *AuthenticatorConfig
	validity time.Duration
	log      *logrus.Entry
	site     string
}

// New creates an instance of the authenticator
func New(c *AuthenticatorConfig, log *logrus.Entry, site string) (a *Authenticator, err error) {
	validity, err := time.ParseDuration(c.TokenValidity)
	if err != nil {
		return nil, errors.Wrap(err, "invalid token validity")
	}

	a = &Authenticator{
		c:        c,
		validity: validity,
		log:      log.WithField("authenticator", "userlist"),
		site:     site,
	}

	return a, nil
}

// Login logs someone in using a configured user list
func (a *Authenticator) Login(req *models.LoginRequest) (resp *models.LoginResponse) {
	timer := authenticators.ProcessTime.WithLabelValues(a.site, "userlist")
	obs := prometheus.NewTimer(timer)
	defer obs.ObserveDuration()

	resp = a.processLogin(req)
	if resp.Error != "" {
		authenticators.ErrCtr.WithLabelValues(a.site, "userlist").Inc()
	}

	return resp
}

func (a *Authenticator) processLogin(req *models.LoginRequest) (resp *models.LoginResponse) {
	resp = &models.LoginResponse{}

	user := a.getUser(req.Username)
	if user == nil {
		a.log.Warnf("Login failed for unknown user %s", req.Username)
		resp.Error = "Login failed"
		return
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password))
	if err != nil {
		a.log.Warnf("Login failed for user %s due to incorrect password", req.Username)
		resp.Error = "Login failed"
		return
	}

	claims := map[string]interface{}{
		"exp":      time.Now().UTC().Add(a.validity).Unix(),
		"nbf":      time.Now().UTC().Add(-1 * time.Minute).Unix(),
		"iat":      time.Now().UTC().Unix(),
		"iss":      "Choria Userlist Authenticator",
		"callerid": fmt.Sprintf("up=%s", req.Username),
		"sub":      fmt.Sprintf("up=%s", req.Username),
		"agents":   user.ACLs,
	}

	policy, err := user.OpenPolicy()
	if err != nil {
		a.log.Warnf("Reading OPA policy for user %s failed: %s", req.Username, err)
		resp.Error = "Login failed"
		return
	}

	if policy != "" {
		claims["opa_policy"] = policy
	}

	token := jwt.NewWithClaims(jwt.GetSigningMethod("RS512"), jwt.MapClaims(claims))

	signKey, err := a.signKey()
	if err != nil {
		a.log.Errorf("Could not load signing key during login request for user %s: %s: %s", req.Username, a.c.SigningKey, err)
		resp.Error = "Could not load signing key from disk"
		return
	}

	signed, err := token.SignedString(signKey)
	if err != nil {
		a.log.Errorf("Could not sign JWT for %s: %s", req.Username, err)
		resp.Error = "Could not sign JWT token"
		return
	}

	resp.Token = signed

	a.log.Infof("Logged in user %s", req.Username)

	return resp

}

func (a *Authenticator) getUser(u string) *User {
	for _, user := range a.c.Users {
		if user.Username == u {
			return user
		}
	}

	return nil
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
