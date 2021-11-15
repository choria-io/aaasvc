package authorizers

import (
	"github.com/choria-io/go-choria/protocol"
	"github.com/choria-io/go-choria/tokens"
)

// Authorizer is used to authorize a request based on its JWT claims
type Authorizer interface {
	// Authorize should check if the request should be allowed
	Authorize(req protocol.Request, claims *tokens.ClientIDClaims) (allow bool, err error)
}
