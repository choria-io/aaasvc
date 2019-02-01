// Package basicjwt is a signer that parse a JWT token and approves requests based
// on the claims within it.
//
// There should be 2 non standard claims in the JWT token:
//
// "callerid" - a string that will be set as the caller id of signed requests in the form of foo=bar
//
// "agents" - a slice of strings for which actions to allow, used by the authorizers like actionlist
//
// The agents claim is not required for basic token handling and authorizers other than actionlist might
// need other claims, see the docs for the authorizers you wish to use
package basicjwt

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/choria-io/aaasvc/auditors"
	"github.com/choria-io/aaasvc/signers"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/choria-io/aaasvc/api/gen/models"
	"github.com/choria-io/aaasvc/authorizers"
	"github.com/choria-io/go-choria/choria"
	"github.com/choria-io/go-protocol/protocol"
	v1 "github.com/choria-io/go-protocol/protocol/v1"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/tidwall/gjson"
)

// SignerConfig is configuration for the BasicJWT signer type
type SignerConfig struct {
	// SigningPubKey is the public certificate of the key used to sign the JWT
	SigningPubKey string `json:"signing_certificate"`

	// MaxValidity is the maximum token validity from current time to sign, this is to avoid someone issuing infinite or many year long tokens that can be a real problem should they leak
	MaxValidity string `json:"max_validity"`
}

// BasicJWT is a very basic JWT based signer
type BasicJWT struct {
	maxExp time.Duration
	site   string
	pubkey string
	auth   authorizers.Authorizer
	audit  []auditors.Auditor
	fw     *choria.Framework
	log    *logrus.Entry
}

// New creates a new instance of the BasicJWT signer
func New(fw *choria.Framework, c *SignerConfig, site string) (signer *BasicJWT, err error) {
	if c.MaxValidity == "" {
		return nil, fmt.Errorf("max_validity is required")
	}

	d, err := time.ParseDuration(c.MaxValidity)
	if err != nil {
		return nil, fmt.Errorf("invalid max_validity duration: %s", err)
	}

	return &BasicJWT{
		maxExp: d,
		pubkey: c.SigningPubKey,
		audit:  []auditors.Auditor{},
		fw:     fw,
		log:    fw.Logger("signer").WithField("signer", "basicjwt"),
		site:   site,
	}, nil
}

// SetAuditors adds auditors to be called when dealing with signing requests
func (s *BasicJWT) SetAuditors(as ...auditors.Auditor) {
	for _, auditor := range as {
		s.audit = append(s.audit, auditor)
	}
}

// SetAuthorizer configures the authorizer to use
func (s *BasicJWT) SetAuthorizer(a authorizers.Authorizer) {
	s.auth = a
}

// Sign creates a new secure request from the given request after authz
//
// - The token is validated for time etc
// - The request is parsed into a choria v1.Request
// - If the request matches the claims in the JWT caller is set to jc=<user>
// - A v1.SecureRequest is made and returned
func (s *BasicJWT) Sign(req *models.SignRequest) (sr *models.SignResponse) {
	sr = s.sign(req)

	if sr.Error != "" {
		signers.ErrorCtr.WithLabelValues(s.site, "basicjwt").Inc()
		signers.DenyCtr.WithLabelValues(s.site, "basicjwt").Inc()
	} else {
		signers.AllowedCtr.WithLabelValues(s.site, "basicjwt").Inc()
	}

	return sr
}

func (s *BasicJWT) sign(req *models.SignRequest) (sr *models.SignResponse) {
	sr = &models.SignResponse{}

	request, err := newRequestFromJSON([]byte(req.Request))
	if err != nil {
		s.logAndSetErr(sr, "Could not parse request: %s", err)
		return sr
	}

	_, claims, err := s.parseJWT(req.Token)
	if err != nil {
		s.auditRequest(auditors.Deny, request)
		s.logAndSetErr(sr, "Could not parse token: %s", err)
		return sr
	}

	err = s.setCaller(request, claims)
	if err != nil {
		s.auditRequest(auditors.Deny, request)
		s.logAndSetErr(sr, "Could not override caller id: %s", err)
		return sr
	}

	allowed, err := s.auth.Authorize(request, claims)
	if err != nil {
		s.auditRequest(auditors.Deny, request)
		s.logAndSetErr(sr, "Could not authorize request: %s", err)
		return sr
	}

	if !allowed {
		s.auditRequest(auditors.Deny, request)
		sr.Error = "Not allowed to perform request"
		s.log.Warnf("Denying request %s from %s@%s for %s", request.RequestID(), request.CallerID(), request.SenderID(), request.Agent())
		return sr
	}

	s.auditRequest(auditors.Allow, request)

	srequest, err := s.fw.NewSecureRequest(request)
	if err != nil {
		s.logAndSetErr(sr, "Could not create secure request: %s", err)
		return sr
	}

	srj, err := srequest.JSON()
	if err != nil {
		s.logAndSetErr(sr, "Could not encode secure request to JSON: %s", err)
		return sr
	}

	sr.SecureRequest = []byte(srj)

	s.log.Infof("Allowing request %s from %s@%s for %s", request.RequestID(), request.CallerID(), request.SenderID(), request.Agent())

	return sr
}

func (s *BasicJWT) logAndSetErr(resp *models.SignResponse, msg string, err error) {
	resp.Error = fmt.Sprintf(msg, err)
	s.log.Warnf(resp.Error)
}

func (s *BasicJWT) auditRequest(action auditors.Action, request protocol.Request) {
	for _, a := range s.audit {
		a.Audit(action, request.CallerID(), request)
	}
}

// sets the caller
func (s *BasicJWT) setCaller(req protocol.Request, claims jwt.MapClaims) error {
	caller, err := s.caller(claims)
	if err != nil {
		return errors.Wrap(err, "could not set caller")
	}

	caller = strings.Replace(caller, "@", "_", -1)
	caller = strings.Replace(caller, ".", "_", -1)

	req.SetCallerID(caller)

	return nil
}

func (s *BasicJWT) caller(claims jwt.MapClaims) (caller string, err error) {
	caller, ok := claims["callerid"].(string)
	if !ok {
		return "", fmt.Errorf("invalid callerid in claims")
	}

	return caller, nil
}

func (s *BasicJWT) signKey() (*rsa.PublicKey, error) {
	certBytes, err := ioutil.ReadFile(s.pubkey)
	if err != nil {
		return nil, errors.Wrap(err, "could not read")
	}

	signKey, err := jwt.ParseRSAPublicKeyFromPEM(certBytes)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse")
	}

	return signKey, nil
}

func (s *BasicJWT) parseJWT(req string) (token *jwt.Token, claims jwt.MapClaims, err error) {
	signKey, err := s.signKey()
	if err != nil {
		return nil, nil, errors.Wrapf(err, "could not read verifying key %s", s.pubkey)
	}

	token, err = jwt.Parse(req, func(token *jwt.Token) (interface{}, error) {
		return signKey, nil
	})
	if err != nil {
		signers.InvalidTokenCtr.WithLabelValues(s.site, "basicjwt").Inc()
		return nil, nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		signers.InvalidTokenCtr.WithLabelValues(s.site, "basicjwt").Inc()
		return nil, nil, fmt.Errorf("invalid claims body received")
	}

	err = claims.Valid()
	if err != nil {
		signers.InvalidTokenCtr.WithLabelValues(s.site, "basicjwt").Inc()
		return nil, nil, fmt.Errorf("invalid claims: %s", err)
	}

	if !verifyExp(claims, jwt.TimeFunc().Add(s.maxExp)) {
		signers.InvalidTokenCtr.WithLabelValues(s.site, "basicjwt").Inc()
		return nil, nil, fmt.Errorf("invalid claims: expiry is not set or it is too far in the future")
	}

	return token, claims, nil
}

func verifyExp(claims jwt.MapClaims, maxAge time.Time) bool {
	claimExp := int64(0)

	switch exp := claims["exp"].(type) {
	case float64:
		claimExp = int64(exp)
	case json.Number:
		claimExp, _ = exp.Int64()
	default:
		return false
	}

	if claimExp == 0 {
		return false
	}

	if claimExp > maxAge.Unix() {
		return false
	}

	return true
}

// Parse the JSON request and if its a v1 choria request creates a v1.Request
func newRequestFromJSON(jreq []byte) (protocol.Request, error) {
	version := gjson.GetBytes(jreq, "protocol").String()
	if version != "choria:request:1" {
		return nil, fmt.Errorf("Invalid request version '%s' expected choria:request:1", version)
	}

	request, err := v1.NewRequest("", "", "", 0, "", "mcollective")
	if err != nil {
		return nil, fmt.Errorf("Could not parse request: %s", err)
	}

	err = json.Unmarshal(jreq, request)
	if err != nil {
		return nil, fmt.Errorf("Could not parse request: %s", err)
	}

	return request, nil
}
