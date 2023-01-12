package userlist

import (
	"os"
	"sync"

	"github.com/choria-io/tokens"
)

// User is a choria user
type User struct {
	// Username in plain text
	Username string `json:"username"`

	// Password is a bcrypted password
	Password string `json:"password"`

	// Organization is a org name the user belongs to
	Organization string `json:"organization"`

	// ACLs are for the action list authorizer
	ACLs []string `json:"acls"`

	// OPAPolicy is a string holding a Open Policy Agent rego policy
	OPAPolicy string `json:"opa_policy"`

	// OPAPolicyFile is the path to a rego file to embed as the policy for this user
	OPAPolicyFile string `json:"opa_policy_file"`

	// Properties are free form additional information to add about a user, this can be
	// referenced later in a signer or other systems, mostly unused by core choria features atm
	Properties map[string]string `json:"properties"`

	// Permissions are additional abilities assigned to the user over and above basic Choria access
	// use these to allow Streams admin using JWT auth for example
	Permissions *tokens.ClientPermissions `json:"broker_permissions"`

	sync.Mutex
}

// OpenPolicy retrieves the OPA Policy either from `OPAPolicy` or by reading the file in `OPAPolicyFile`
func (u *User) OpenPolicy() (policy string, err error) {
	u.Lock()
	defer u.Unlock()

	if u.OPAPolicy != "" {
		return u.OPAPolicy, nil
	}

	if u.OPAPolicyFile == "" {
		return "", nil
	}

	out, err := os.ReadFile(u.OPAPolicyFile)
	if err != nil {
		return "", err
	}

	return string(out), nil
}
