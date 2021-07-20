package authorizers

import (
	"github.com/choria-io/go-choria/protocol"
	"github.com/golang-jwt/jwt"
)

// Authorizer is used to authorize a request based on its JWT claims
type Authorizer interface {
	// Authorize should check if the request should be allowed
	Authorize(req protocol.Request, claims jwt.MapClaims) (allow bool, err error)
}
