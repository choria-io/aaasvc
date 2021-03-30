package userlist

import (
	"io/ioutil"
	"sync"
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
	// referenced later in an authorizer like the Open Policy one
	Properties map[string]string `json:"properties"`

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

	out, err := ioutil.ReadFile(u.OPAPolicyFile)
	if err != nil {
		return "", err
	}

	return string(out), nil
}
