package opa

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	"github.com/choria-io/go-choria/protocol"
	"github.com/choria-io/go-choria/providers/agent/mcorpc"
	"github.com/choria-io/go-choria/tokens"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

func TestWithGinkgo(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Authorizers/OPA")
}

var _ = Describe("Authorizers/OPA", func() {
	var auth *Authorizer
	var log *logrus.Entry
	var req *mcorpc.Request
	var claims *tokens.ClientIDClaims

	BeforeEach(func() {
		logger := logrus.New()
		logger.Out = GinkgoWriter
		logger.Level = logrus.DebugLevel
		log = logrus.NewEntry(logger)
		auth = &Authorizer{log: log, site: "ginkgo"}
		claims = &tokens.ClientIDClaims{}

		req = &mcorpc.Request{
			Agent:      "myco",
			Action:     "deploy",
			Data:       json.RawMessage(`{"component":"frontend"}`),
			SenderID:   "some.node",
			Collective: "ginkgo",
			TTL:        60,
			Time:       time.Now(),
			Filter:     protocol.NewFilter(),
		}
	})

	It("Should allow common scenarios", func() {
		req.Filter.AddClassFilter("apache")
		req.Filter.AddIdentityFilter("some.node")
		req.Filter.AddFactFilter("country", "==", "mt")

		claims.CallerID = "up=bob"
		claims.UserProperties = map[string]string{
			"group": "admins",
		}

		for r := 1; r <= 5; r++ {
			policy := readFixture(fmt.Sprintf("testdata/scenario%d.rego", r))
			claims.OPAPolicy = policy

			allowed, err := auth.evaluatePolicy(req, policy, claims)
			Expect(err).ToNot(HaveOccurred())
			Expect(allowed).To(BeTrue())
		}
	})

	It("Should fail on all common scenarios", func() {
		policy := readFixture("testdata/scenario5.rego")
		claims.OPAPolicy = policy
		claims.CallerID = "up=bob"
		claims.UserProperties = map[string]string{
			"group": "admins",
		}

		req.Filter.AddClassFilter("apache")
		req.Filter.AddIdentityFilter("some.node")
		req.Filter.AddFactFilter("country", "==", "mt")

		allowed, err := auth.evaluatePolicy(req, policy, claims)
		Expect(err).ToNot(HaveOccurred())
		Expect(allowed).To(BeTrue())

		auth.site = "x"
		allowed, err = auth.evaluatePolicy(req, policy, claims)
		Expect(err).ToNot(HaveOccurred())
		Expect(allowed).To(BeFalse())
	})
})

func readFixture(f string) string {
	c, err := ioutil.ReadFile(f)
	if err != nil {
		panic(err)
	}

	return string(c)
}
