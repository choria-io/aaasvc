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
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/choria-io/aaasvc/auditors"
	"github.com/choria-io/aaasvc/signers"
	"github.com/choria-io/go-choria/choria"
	cconf "github.com/choria-io/go-choria/config"
	"github.com/choria-io/go-choria/inter"
	v2 "github.com/choria-io/go-choria/protocol/v2"
	"github.com/choria-io/go-choria/tokens"
	"github.com/sirupsen/logrus"

	"github.com/choria-io/aaasvc/api/gen/models"
	"github.com/choria-io/aaasvc/authorizers"
	"github.com/choria-io/go-choria/protocol"
	v1 "github.com/choria-io/go-choria/protocol/v1"
)

// SignerConfig is configuration for the BasicJWT signer type
type SignerConfig struct {
	// SigningPubKey is the public certificate of the key used to sign the user JWT - typically the authenticator
	SigningPubKey string `json:"signing_certificate"`

	// SigningToken is the JWT used for signing requests, should have delegate authority
	SigningToken string `json:"signing_token"`

	// SigningSeed is used with SigningToken to sign secure requests
	SigningSeed string `json:"signing_seed"`

	// MaxValidity is the maximum token validity from current time to sign, this is to avoid someone issuing infinite or many year long tokens that can be a real problem should they leak
	MaxValidity string `json:"max_validity"`

	// ChoriaService enables the choria service to sign requests
	ChoriaService bool `json:"choria_service"`

	// AllowBearerTokens makes the signature of the request optional
	AllowBearerTokens bool `json:"allow_bearer_tokens"`
}

// BasicJWT is a very basic JWT based signer
type BasicJWT struct {
	maxExp            time.Duration
	site              string
	pubkey            string
	signerToken       string
	signerSeed        string
	allowBearerTokens bool
	auth              authorizers.Authorizer
	audit             []auditors.Auditor
	fw                inter.Framework
	log               *logrus.Entry
}

// New creates a new instance of the BasicJWT signer
func New(fw inter.Framework, c *SignerConfig, site string) (*BasicJWT, error) {
	if c.MaxValidity == "" {
		return nil, fmt.Errorf("max_validity is required")
	}

	d, err := time.ParseDuration(c.MaxValidity)
	if err != nil {
		return nil, fmt.Errorf("invalid max_validity duration: %s", err)
	}

	signer := &BasicJWT{
		maxExp:            d,
		pubkey:            c.SigningPubKey,
		signerToken:       c.SigningToken,
		signerSeed:        c.SigningSeed,
		allowBearerTokens: c.AllowBearerTokens,
		audit:             []auditors.Auditor{},
		fw:                fw,
		site:              site,
	}

	// fw is the same as the one starting the service generally and when using issuers
	// and tokens it must be a server token, which cannot sign requests
	//
	// thus we need to create a new fw to get a new security provider using these
	// specific keys and tokens for a client with delegation authority to do secure
	// request signing. We inherit settings like logs and such to keep things a bit sane
	if c.SigningSeed != "" {
		cfg, err := cconf.NewDefaultConfig()
		if err != nil {
			return nil, err
		}
		cfg.Choria.SecurityProvider = "choria"
		cfg.Choria.ChoriaSecuritySeedFile = c.SigningSeed
		cfg.Choria.ChoriaSecurityTokenFile = c.SigningToken
		cfg.LogFile = fw.Configuration().LogFile
		cfg.LogLevel = fw.Configuration().LogLevel

		fw, err := choria.NewWithConfig(cfg)
		if err != nil {
			return nil, err
		}

		signer.fw = fw
	}

	signer.log = signer.fw.Logger("signer").WithField("signer", "basicjwt")

	return signer, nil
}

// SetAuditors adds auditors to be called when dealing with signing requests
func (s *BasicJWT) SetAuditors(as ...auditors.Auditor) {
	s.audit = append(s.audit, as...)
}

// SetAuthorizer configures the authorizer to use
func (s *BasicJWT) SetAuthorizer(a authorizers.Authorizer) {
	s.auth = a
}

// SignRequest signs req based on token using same rules as Sign()
func (s *BasicJWT) SignRequest(req []byte, token string, signature string) (bool, []byte, error) {
	return s.signRequest(req, token, signature)
}

// Sign creates a new secure request from the given request after authz
//
// - The token is validated for time etc
// - The request is parsed into a choria protocol.Request
// - If the request matches the claims in the JWT caller is set to jc=<user>
// - A protocol.SecureRequest is made and returned
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

func (s *BasicJWT) checkSignature(req []byte, signature string, claims *tokens.ClientIDClaims) error {
	hasSig := len(signature) > 0

	// no signature is ok when we are configured to allow bearer tokens
	if s.allowBearerTokens && !hasSig {
		return nil
	}

	if !hasSig {
		return fmt.Errorf("no signature")
	}

	pk, err := hex.DecodeString(claims.PublicKey)
	if err != nil {
		return fmt.Errorf("invalid public key in token: %w", err)
	}

	sig, err := hex.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("invalid signature in request: %w", err)
	}

	ok, err := choria.Ed24419Verify(pk, req, sig)
	if err != nil {
		return fmt.Errorf("signature verification failed: %v", err)
	}

	if !ok {
		return fmt.Errorf("invalid request signature")
	}

	return nil
}

func (s *BasicJWT) signRequest(req []byte, token string, signature string) (bool, []byte, error) {
	request, err := newRequestFromJSON(req)
	if err != nil {
		return false, nil, fmt.Errorf("invalid request: %s", err)
	}

	claims, err := s.parseJWT(token)
	if err != nil {
		s.auditRequest(auditors.Deny, request)
		return false, nil, fmt.Errorf("invalid token: %s", err)
	}

	err = s.checkSignature(req, signature, claims)
	if err != nil {
		s.auditRequest(auditors.Deny, request)
		return false, nil, fmt.Errorf("invalid signature: %s", err)
	}

	err = s.setCaller(request, claims)
	if err != nil {
		s.auditRequest(auditors.Deny, request)
		return false, nil, fmt.Errorf("could not set caller id: %s", err)
	}

	allowed, err := s.auth.Authorize(request, claims)
	if err != nil {
		s.auditRequest(auditors.Deny, request)
		return false, nil, fmt.Errorf("authorization failed: %s", err)
	}

	if !allowed {
		s.auditRequest(auditors.Deny, request)
		s.log.Warnf("Denying request %s from %s@%s for %s", request.RequestID(), request.CallerID(), request.SenderID(), request.Agent())
		return false, nil, nil
	}

	s.auditRequest(auditors.Allow, request)

	srequest, err := s.fw.NewSecureRequest(context.Background(), request)
	if err != nil {
		return false, nil, fmt.Errorf("secure request failed: %s", err)
	}

	if s.signerToken != "" {
		s.log.Debugf("Signing secure request using %s", s.signerToken)
		pk, err := os.ReadFile(s.signerToken)
		if err != nil {
			return false, nil, fmt.Errorf("setting signing token failed: %w", err)
		}

		srequest.SetSigner(pk)
	}

	srj, err := srequest.JSON()
	if err != nil {
		return false, nil, fmt.Errorf("secure request failed: %s", err)
	}

	s.log.Infof("Allowing request %s from %s@%s for %s", request.RequestID(), request.CallerID(), request.SenderID(), request.Agent())

	return true, srj, nil
}

func (s *BasicJWT) sign(req *models.SignRequest) (sr *models.SignResponse) {
	sr = &models.SignResponse{}

	allowed, signed, err := s.signRequest(req.Request, req.Token, req.Signature)
	switch {
	case !allowed && err == nil:
		sr.Error = "Request denied"

	case err != nil:
		s.log.Warnf("Signing failed: %s", err)
		sr.Error = "Request denied"
		sr.Detail = err.Error()

	case allowed:
		sr.SecureRequest = signed
	}

	return sr
}

func (s *BasicJWT) auditRequest(action auditors.Action, request protocol.Request) {
	for _, a := range s.audit {
		err := a.Audit(action, request.CallerID(), request)
		if err != nil {
			s.log.Errorf("Auditing failed: %s", err)
		}
	}
}

// sets the caller
func (s *BasicJWT) setCaller(req protocol.Request, claims *tokens.ClientIDClaims) error {
	caller := claims.CallerID
	if caller == "" {
		return fmt.Errorf("no caller received in claims")
	}

	caller = strings.Replace(caller, "@", "_", -1)
	caller = strings.Replace(caller, ".", "_", -1)

	req.SetCallerID(caller)

	return nil
}

func (s *BasicJWT) parseJWT(req string) (claims *tokens.ClientIDClaims, err error) {
	claims, err = tokens.ParseClientIDTokenWithKeyfile(req, s.pubkey, true)
	if err != nil {
		signers.InvalidTokenCtr.WithLabelValues(s.site, "basicjwt").Inc()
		return nil, err
	}

	if !verifyExp(claims, s.maxExp) {
		signers.InvalidTokenCtr.WithLabelValues(s.site, "basicjwt").Inc()
		return nil, fmt.Errorf("invalid claims: expiry is not set or it is too far in the future")
	}

	return claims, nil
}

func verifyExp(claims *tokens.ClientIDClaims, maxAge time.Duration) bool {
	// if the special in-jwt flag is set we trust the expires claim without additional
	// checks for maximum length till expires.
	if claims.Permissions != nil && claims.Permissions.ExtendedServiceLifetime {
		return true
	}

	if claims.ExpiresAt == nil {
		return false
	}

	exp := claims.ExpiresAt.Time
	if exp.IsZero() {
		return false
	}

	if time.Until(exp) > maxAge {
		return false
	}

	return true
}

// Parse the JSON request and if its a v1 choria request creates a v1.Request
func newRequestFromJSON(jreq []byte) (protocol.Request, error) {
	version := protocol.VersionFromJSON(jreq)

	switch version {
	case protocol.RequestV1:
		request, err := v1.NewRequest("", "", "", 0, "", "mcollective")
		if err != nil {
			return nil, fmt.Errorf("could not parse request: %s", err)
		}

		err = json.Unmarshal(jreq, request)
		if err != nil {
			return nil, fmt.Errorf("could not parse request: %s", err)
		}

		return request, nil

	case protocol.RequestV2:
		request, err := v2.NewRequest("", "", "", 0, "", "choria")
		if err != nil {
			return nil, fmt.Errorf("could not parse request: %s", err)
		}

		err = json.Unmarshal(jreq, request)
		if err != nil {
			return nil, fmt.Errorf("could not parse request: %s", err)
		}

		return request, nil

	default:
		return nil, fmt.Errorf("unsupported request version '%s'", version.String())
	}
}
