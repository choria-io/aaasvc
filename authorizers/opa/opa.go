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
	"context"
	"encoding/json"
	"fmt"

	"github.com/choria-io/go-choria/client/client"
	"github.com/choria-io/go-choria/opa"
	"github.com/choria-io/go-choria/protocol"
	"github.com/choria-io/go-choria/providers/agent/mcorpc"
	"github.com/choria-io/go-choria/tokens"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
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
	allowed, action, err := a.authorize(req, claims)
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

func (a *Authorizer) authorize(req protocol.Request, claims *tokens.ClientIDClaims) (allowed bool, action string, err error) {
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

	if claims.OPAPolicy == "" {
		return false, req.Agent(), fmt.Errorf("'opa_policy' claim is an empty string, denying request")
	}

	allowed, err = a.evaluatePolicy(rpcreq, claims.OPAPolicy, claims)
	if err != nil {
		return false, req.Agent(), fmt.Errorf("OPA policy evaluation failed: %s", err)
	}

	if allowed {
		a.log.Debugf("Allowing request %s from %s@%s for agent %s#%s", req.RequestID(), req.CallerID(), req.SenderID(), rpcreq.Agent, rpcreq.Action)
	} else {
		a.log.Warnf("Denying request %s from %s@%s for agent %s#%s", req.RequestID(), req.CallerID(), req.SenderID(), rpcreq.Agent, rpcreq.Action)
	}

	return allowed, fmt.Sprintf("%s.%s", rpcreq.Agent, rpcreq.Action), nil
}

func (a *Authorizer) evaluatePolicy(rpcreq *mcorpc.Request, policy string, claims *tokens.ClientIDClaims) (allowed bool, err error) {
	if policy == "" {
		return false, fmt.Errorf("invalid policy given")
	}

	data := make(map[string]any)
	err = json.Unmarshal(rpcreq.Data, &data)
	if err != nil {
		a.log.Errorf("Invalid data: %s", rpcreq.Data)
		return false, fmt.Errorf("could not parse data embedded in request: %v", err)
	}

	eopts := []opa.Option{
		opa.Logger(a.log),
		opa.Policy([]byte(policy)),
		opa.Function(a.regoFunctionsMap(rpcreq)...),
	}

	if a.log.Logger.GetLevel() == logrus.DebugLevel {
		eopts = append(eopts, opa.Trace())
	}

	evaluator, err := opa.New("io.choria.aaasvc", "data.io.choria.aaasvc.allow", eopts...)
	if err != nil {
		return false, fmt.Errorf("could not initialize opa evaluator for request %s: %v", rpcreq.RequestID, err)
	}

	a.log.Infof("Evaluating rego policy found in JWT claim for request %s", rpcreq.RequestID)
	inputs, err := a.regoInputs(rpcreq, data, claims)
	if err != nil {
		return false, err
	}

	allowed, err = evaluator.Evaluate(context.Background(), inputs)
	if err != nil {
		return false, fmt.Errorf("could not evaluate policy for request %s: %s", rpcreq.RequestID, err)
	}

	return allowed, nil
}

func (a *Authorizer) regoInputs(req *mcorpc.Request, data map[string]any, claims *tokens.ClientIDClaims) (map[string]any, error) {
	j, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("could not JSON encode claims")
	}

	cdat := new(map[string]any)
	err = json.Unmarshal(j, &cdat)
	if err != nil {
		return nil, fmt.Errorf("could not JSON decode claims")
	}

	return map[string]any{
		"agent":      req.Agent,
		"action":     req.Action,
		"data":       data,
		"sender":     req.SenderID,
		"collective": req.Collective,
		"ttl":        req.TTL,
		"time":       req.Time,
		"site":       a.site,
		"claims":     cdat,
	}, nil
}

func (a *Authorizer) regoFunctionsMap(req *mcorpc.Request) []func(r *rego.Rego) {
	return []func(r *rego.Rego){
		rego.Function1(&rego.Function{Name: "requires_filter", Decl: types.NewFunction(types.Args(), types.B)}, a.regoFuncRequiresFilter(req)),
		rego.Function1(&rego.Function{Name: "requires_fact_filter", Decl: types.NewFunction(types.Args(types.S), types.B)}, a.regoFuncRequiresFactFilter(req)),
		rego.Function1(&rego.Function{Name: "requires_class_filter", Decl: types.NewFunction(types.Args(types.S), types.B)}, a.regoFuncRequiresClassFilter(req)),
		rego.Function1(&rego.Function{Name: "requires_identity_filter", Decl: types.NewFunction(types.Args(types.S), types.B)}, a.regoFuncRequiresIdentityFilter(req)),
	}
}

func (a *Authorizer) regoFuncRequiresFilter(req *mcorpc.Request) func(_ rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
	return func(_ rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
		// agent is always set so we dont check it else it will always be true
		if len(req.Filter.ClassFilters()) > 0 || len(req.Filter.IdentityFilters()) > 0 || len(req.Filter.FactFilters()) > 0 || len(req.Filter.CompoundFilters()) > 0 {
			return ast.BooleanTerm(true), nil
		}

		return ast.BooleanTerm(false), nil
	}

}

func (a *Authorizer) regoFuncRequiresIdentityFilter(req *mcorpc.Request) func(_ rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
	return func(_ rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
		str, ok := a.Value.(ast.String)
		if !ok {
			return ast.BooleanTerm(false), fmt.Errorf("invalid identity matcher received")
		}

		want := string(str)
		for _, f := range req.Filter.IdentityFilters() {
			if f == want {
				return ast.BooleanTerm(true), nil
			}
		}

		return ast.BooleanTerm(false), nil
	}
}

func (a *Authorizer) regoFuncRequiresClassFilter(req *mcorpc.Request) func(_ rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
	return func(_ rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
		str, ok := a.Value.(ast.String)
		if !ok {
			return ast.BooleanTerm(false), fmt.Errorf("invalid class matcher received")
		}

		want := string(str)

		for _, f := range req.Filter.ClassFilters() {
			if f == want {
				return ast.BooleanTerm(true), nil
			}
		}

		return ast.BooleanTerm(false), nil
	}
}

func (a *Authorizer) regoFuncRequiresFactFilter(req *mcorpc.Request) func(_ rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
	return func(_ rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
		str, ok := a.Value.(ast.String)
		if !ok {
			return ast.BooleanTerm(false), fmt.Errorf("invalid fact matcher received")
		}

		want, err := client.ParseFactFilterString(string(str))
		if err != nil {
			return ast.BooleanTerm(false), fmt.Errorf("invalid fact matcher received: %s", err)
		}

		for _, f := range req.Filter.Fact {
			if want.Fact == f.Fact && want.Operator == f.Operator && want.Value == f.Value {
				return ast.BooleanTerm(true), nil
			}
		}

		return ast.BooleanTerm(false), nil
	}
}
