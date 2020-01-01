package signers

import (
	"sync"

	"github.com/choria-io/aaasvc/authorizers"

	"github.com/choria-io/aaasvc/auditors"

	"github.com/choria-io/aaasvc/api/gen/models"
	"github.com/choria-io/aaasvc/api/gen/restapi/operations"
	"github.com/go-openapi/runtime/middleware"
)

var signer Signer
var mu = &sync.Mutex{}

// Signer is a interface that describes software capable of signing a request
type Signer interface {
	// Sign takes a request and sign it if desired, else setting errors in the sr
	Sign(req *models.SignRequest) *models.SignResponse

	// SetAuditors add auditors to be called after signing actions
	SetAuditors(...auditors.Auditor)

	// SetAuthorizer sets the authorizer to use
	SetAuthorizer(authorizers.Authorizer)
}

// SetSigner sets the signer to use
func SetSigner(s Signer) {
	mu.Lock()
	defer mu.Unlock()

	signer = s
}

// SignHandler is a HTTP middleware handler for signing messages using the signer set by SetSigner
func SignHandler(params operations.PostSignParams) middleware.Responder {
	mu.Lock()
	defer mu.Unlock()

	if signer == nil {
		return operations.NewPostSignOK().WithPayload(&models.SignResponse{Error: "No signer configured"})
	}

	return operations.NewPostSignOK().WithPayload(signer.Sign(params.Request))
}
