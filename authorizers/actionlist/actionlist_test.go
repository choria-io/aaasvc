package actionlist

import (
	"io"
	"testing"

	"github.com/choria-io/tokens"
	"github.com/sirupsen/logrus"

	v1 "github.com/choria-io/go-choria/protocol/v1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestWithGinkgo(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Authorizers/Actionlist")
}

var _ = Describe("Authorizers/Actionlist", func() {
	var (
		auth   Authorizer
		log    *logrus.Entry
		claims *tokens.ClientIDClaims
	)

	BeforeEach(func() {
		logger := logrus.New()
		logger.Out = io.Discard
		log = logrus.NewEntry(logger)
		claims = &tokens.ClientIDClaims{}
		auth = Authorizer{log: log, site: "ginkgo"}
	})

	Describe("Authorize", func() {
		It("Should always allow discovery agent", func() {
			req, err := v1.NewRequest("discovery", "ginkgo.example.net", "choria=ginkgo", 60, "123454", "mcollective")
			Expect(err).ToNot(HaveOccurred())

			allowed, err := auth.Authorize(req, claims)
			Expect(err).ToNot(HaveOccurred())
			Expect(allowed).To(BeTrue())
		})

		It("Should fail disallowed requests", func() {
			claims.AllowedAgents = []string{"nothing.*"}
			req, err := v1.NewRequest("rpcutil", "ginkgo.example.net", "choria=ginkgo", 60, "123454", "mcollective")
			Expect(err).ToNot(HaveOccurred())
			req.SetMessage([]byte(`{"action":"ping", "agent":"rpcutil"}`))

			allowed, err := auth.Authorize(req, claims)
			Expect(err).ToNot(HaveOccurred())
			Expect(allowed).To(BeFalse())
		})
	})
})
