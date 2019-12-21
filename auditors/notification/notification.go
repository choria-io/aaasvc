package notification

import (
	"encoding/json"
)

// SignerAudit is the notification being sent and shall comply with https://choria.io/schemas/choria/signer/v1/signature_audit.json
type SignerAudit struct {
	Protocol string          `json:"protocol"`
	CallerID string          `json:"callerid"`
	Action   string          `json:"action"`
	Site     string          `json:"site"`
	Time     int64           `json:"time"`
	Request  json.RawMessage `json:"request"`
}
