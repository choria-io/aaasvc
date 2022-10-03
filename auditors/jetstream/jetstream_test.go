package jetstream

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/choria-io/aaasvc/auditors"
	"github.com/choria-io/aaasvc/auditors/notification"

	v1 "github.com/choria-io/go-choria/protocol/v1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestWithGinkgo(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Auditors/JetStream")
}

var _ = Describe("Auditors/JetStream", func() {
	Describe("Audit", func() {
		It("Should publish valid audit messages", func() {
			auditor := &JetStream{
				outbox: make(chan interface{}, 1000),
				site:   "GINKGO",
			}

			rpcreq, err := v1.NewRequest("ginkgo", "ginkgo.example.net", "choria=ginkgo", 60, "9b3a0089dbe0d896c1b79bbc12d61212", "mcollective")
			Expect(err).ToNot(HaveOccurred())
			rpcreq.SetMessage([]byte("{}"))

			j, err := rpcreq.JSON()
			Expect(err).ToNot(HaveOccurred())

			auditor.Audit(auditors.Allow, "choria=allowed", rpcreq)
			auditor.Audit(auditors.Deny, "choria=denied", rpcreq)

			msg := <-auditor.outbox
			n, ok := msg.(*notification.SignerAudit)
			Expect(ok).To(BeTrue())
			Expect(n.Protocol).To(Equal("io.choria.signer.v1.signature_audit"))
			Expect(n.CallerID).To(Equal("choria=allowed"))
			Expect(n.Action).To(Equal("allow"))
			Expect(n.Site).To(Equal("GINKGO"))
			Expect(n.Time).To(BeNumerically(">=", int64(time.Now().UTC().Unix())))
			Expect(n.Request).To(Equal(json.RawMessage(j)))

			msg = <-auditor.outbox
			n, ok = msg.(*notification.SignerAudit)
			Expect(ok).To(BeTrue())
			Expect(n.Protocol).To(Equal("io.choria.signer.v1.signature_audit"))
			Expect(n.CallerID).To(Equal("choria=denied"))
			Expect(n.Action).To(Equal("deny"))
			Expect(n.Site).To(Equal("GINKGO"))
			Expect(n.Time).To(BeNumerically(">=", int64(time.Now().UTC().Unix())))
			Expect(n.Request).To(Equal(json.RawMessage(j)))
		})
	})
})
