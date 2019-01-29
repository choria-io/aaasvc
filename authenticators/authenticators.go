package authenticators

import (
	"sync"

	"github.com/go-openapi/runtime/middleware"
	"github.com/choria-io/aaasvc/api/gen/models"
	"github.com/choria-io/aaasvc/api/gen/restapi/operations"
)

var authenticator Authenticator
var mu = &sync.Mutex{}

// Authenticator providers user authentication
type Authenticator interface {
	Login(*models.LoginRequest) *models.LoginResponse
}

// SetAuthenticator sets the authenticator to use
func SetAuthenticator(a Authenticator) {
	mu.Lock()
	defer mu.Unlock()

	authenticator = a
}

// LoginHandler is a HTTP middleware handler for performing logins using the configured authenticator
func LoginHandler(params operations.PostLoginParams) middleware.Responder {
	mu.Lock()
	defer mu.Unlock()

	if authenticator == nil {
		return operations.NewPostLoginOK().WithPayload(&models.LoginResponse{Error: "No authenticator configured"})
	}

	return operations.NewPostLoginOK().WithPayload(authenticator.Login(params.Request))
}
