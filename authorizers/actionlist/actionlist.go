// Package actionlist is a Authorizer that looks at specific claims in a JWT token and allow requests based on the approved list of actions.
//
// The JWT claims must have a "agents" claim that is a list of a strings with the following possible values:
//
// Allow all requests to any agent and action
//   []string{"*"}
//
// Allow requests to all actions of rpcutil agent
//  []string{"rpcutil.*"}
//
// Allow requests only to rpcutil agent ping action
//  []string{"rpcutil.ping"}
//
// Multiple claims are parsed in a first match order, default is deny
//
//  []string{"rpcutil.*", "package.status"}
//
// Here we have 2 allow rules, it will keep looking till it finds a match and then default deny.
package actionlist

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/choria-io/aaasvc/authorizers"
	"github.com/choria-io/go-choria/protocol"
	"github.com/choria-io/go-choria/providers/agent/mcorpc"
	"github.com/golang-jwt/jwt"
	"github.com/sirupsen/logrus"
)

// Authorizer authorizes requests based on their agent and action
type Authorizer struct {
	log  *logrus.Entry
	site string
}

// New creates a new actionlist authorizer
func New(log *logrus.Entry, site string) *Authorizer {
	return &Authorizer{
		site: site,
		log:  log.WithField("authorizer", "actionlist"),
	}
}

// Authorize implements authorizers.Authorizer
func (a *Authorizer) Authorize(req protocol.Request, claims jwt.MapClaims) (allowed bool, err error) {
	allowed, action, err := a.authorize(req, claims)

	if err != nil {
		authorizers.ErrCtr.WithLabelValues(a.site, "actionlist").Inc()
	}

	if allowed {
		authorizers.AllowCtr.WithLabelValues(a.site, "actionlist", action).Inc()
	} else {
		authorizers.DenyCtr.WithLabelValues(a.site, "actionlist", action).Inc()
	}

	return allowed, err
}

func (a *Authorizer) authorize(req protocol.Request, claims jwt.MapClaims) (allowed bool, action string, err error) {
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
	err = json.Unmarshal([]byte(req.Message()), rpcreq)
	if err != nil {
		a.log.Warnf("Could not parse RPC request in request %s from %s@%s for agent %s", req.RequestID(), req.CallerID(), req.SenderID(), req.Agent())
		return false, req.Agent(), err
	}

	ok, err := validateAction(rpcreq.Agent, rpcreq.Action, claims, a.log)
	if err != nil {
		a.log.Warnf("Validating request %s from %s@%s for agent %s failed: %s", req.RequestID(), req.CallerID(), req.SenderID(), rpcreq.Agent, err)
	}

	if ok {
		a.log.Debugf("Allowing request %s from %s@%s for agent %s#%s", req.RequestID(), req.CallerID(), req.SenderID(), rpcreq.Agent, rpcreq.Action)
	} else {
		a.log.Warnf("Denying request %s from %s@%s for agent %s#%s", req.RequestID(), req.CallerID(), req.SenderID(), rpcreq.Agent, rpcreq.Action)
	}

	return ok, fmt.Sprintf("%s.%s", rpcreq.Agent, rpcreq.Action), err
}

func validateAction(agent string, action string, claims jwt.MapClaims, log *logrus.Entry) (ok bool, err error) {
	agents, ok := claims["agents"].([]interface{})
	if !ok {
		return false, fmt.Errorf("invalid agent claims")
	}

	for _, allow := range agents {
		claim, ok := allow.(string)
		if !ok {
			return false, fmt.Errorf("invalid agent claim found in token %s", allow)
		}

		// all things are allowed
		if claim == "*" {
			return true, nil
		}

		parts := strings.Split(claim, ".")
		if len(parts) != 2 {
			return false, fmt.Errorf("invalid agent claim found in token %s", claim)
		}

		// its a claim for a different agent so pass, no need to check it here
		if agent != parts[0] {
			continue
		}

		// agent matches, action is * so allow it
		if parts[1] == "*" {
			return true, nil
		}

		// agent matches, action matches, allow it
		if action == parts[1] {
			return true, nil
		}
	}

	// nothing matched all passed or list is empty, deny all
	return false, nil
}
