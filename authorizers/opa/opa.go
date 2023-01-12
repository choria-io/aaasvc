// Package opa is a Authorizer that reads Open Policy Agent Rego policies from a `opa_policy` claim in a JWT token
// and allow requests based on evaluation of the policy
//
// The only query done against the policy is `choria.aaa.policy.allow`, you should write your policies default deny
// and allow only specific cases.
//
// A number of custom functions exist to assert over filters:
//
// * `requires_filter()` - ensures that at least one of identity, class, compound of fact filters is not empty
// * `requires_fact_filter("country=mt")` - ensures the specific fact filter is present in the request
// * `requires_class_filter("apache")` - ensures the specific class filter is present in the request
// * `requires_identity_filter("some.node")` - ensures the specific identity filter is present in the request
//
// The following data is exposed to rego:
//
// * `agent` - the agent being invoked
// * `action` - the action being invoked
// * `data` - the contents of the request - all the inputs
// * `sender` - the sender host
// * `collective` - the targeted sub collective
// * `ttl` - the ttl of the request
// * `time` - the time the request was made
// * `site` - the site hosting the aaasvcs (from its config)
// * `claims` - all the JWT claims
package opa

import (
	"encoding/json"
	"fmt"

	"github.com/choria-io/go-choria/protocol"
	"github.com/choria-io/go-choria/providers/agent/mcorpc"
	"github.com/choria-io/tokens"
	"github.com/sirupsen/logrus"

	"github.com/choria-io/aaasvc/authorizers"
)

// Authorizer authorizes requests based on Open Policy Agent policies
type Authorizer struct {
	log  *logrus.Entry
	site string
}

// New creates a new Open Policy Agent authorizer
func New(log *logrus.Entry, site string) *Authorizer {
	return &Authorizer{
		log:  log,
		site: site,
	}
}

// Authorize implements authorizers.Authorizer
func (a *Authorizer) Authorize(req protocol.Request, claims *tokens.ClientIDClaims) (allowed bool, err error) {
	allowed, action, err := a.authorizeProtoRequest(req, claims)
	if err != nil {
		authorizers.ErrCtr.WithLabelValues(a.site, "opa").Inc()
	}

	if allowed {
		authorizers.AllowCtr.WithLabelValues(a.site, "opa", action).Inc()
	} else {
		authorizers.DenyCtr.WithLabelValues(a.site, "opa", action).Inc()
	}

	return allowed, err
}

func (a *Authorizer) authorizeProtoRequest(req protocol.Request, claims *tokens.ClientIDClaims) (allowed bool, action string, err error) {
	if req.Agent() == "discovery" {
		a.log.Debugf("Allowing discovery request %s from %s@%s", req.RequestID(), req.CallerID(), req.SenderID())
		return true, req.Agent(), nil
	}

	err = claims.Valid()
	if err != nil {
		a.log.Warnf("Received request %s from %s@%s for agent %s with invalid JWT claims", req.RequestID(), req.CallerID(), req.SenderID(), req.Agent())
		return false, req.Agent(), fmt.Errorf("invalid claims body received: %s", err)
	}

	rpcreq := &mcorpc.Request{}
	err = json.Unmarshal(req.Message(), rpcreq)
	if err != nil {
		a.log.Warnf("Could not parse RPC request in request %s from %s@%s for agent %s", req.RequestID(), req.CallerID(), req.SenderID(), req.Agent())
		return false, req.Agent(), err
	}

	allowed, action, err = a.authorize(rpcreq, claims)
	if allowed {
		a.log.Debugf("Allowing request %s from %s@%s for agent %s#%s", rpcreq.RequestID, req.CallerID(), req.SenderID(), rpcreq.Agent, rpcreq.Action)
	} else {
		a.log.Warnf("Denying request %s from %s@%s for agent %s#%s", req.RequestID(), req.CallerID(), req.SenderID(), rpcreq.Agent, rpcreq.Action)
	}

	return allowed, action, err
}

func (a *Authorizer) authorize(rpcreq *mcorpc.Request, claims *tokens.ClientIDClaims) (allowed bool, action string, err error) {
	if claims.OPAPolicy == "" {
		return false, fmt.Sprintf("%s.%s", rpcreq.Agent, rpcreq.Action), fmt.Errorf("'opa_policy' claim is an empty string, denying request")
	}

	allowed, err = mcorpc.EvaluateOpenPolicyAgentPolicy(rpcreq, claims.OPAPolicy, claims, a.site, a.log)
	if err != nil {
		return false, fmt.Sprintf("%s.%s", rpcreq.Agent, rpcreq.Action), fmt.Errorf("OPA policy evaluation failed: %s", err)
	}

	return allowed, fmt.Sprintf("%s.%s", rpcreq.Agent, rpcreq.Action), nil
}
