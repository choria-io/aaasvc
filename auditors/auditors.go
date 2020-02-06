package auditors

import (
	"github.com/choria-io/go-choria/protocol"
)

// Action is the action taken by the authorizer on a specific message
type Action int

var (
	// Unknown action
	Unknown Action = 0

	// Allow indicates the message was allowed
	Allow Action = 1

	// Deny indicates the message was denied
	Deny Action = 2

	// ActionNames are descriptive names for actions to be used in logging etc
	ActionNames = map[Action]string{
		Unknown: "unknown",
		Allow:   "allow",
		Deny:    "deny",
	}
)

// Auditor is a plugin that audits the action taken on a request
type Auditor interface {
	// Audit should audit the action taken on a message
	Audit(act Action, caller string, req protocol.Request) error
}
