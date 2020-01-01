package opa

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	"github.com/choria-io/go-protocol/protocol"
	"github.com/choria-io/mcorpc-agent-provider/mcorpc"
	jwt "github.com/dgrijalva/jwt-go"
	. "github.com/onsi/ginkgo"
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
	var claims jwt.MapClaims

	BeforeEach(func() {
		logger := logrus.New()
		logger.Out = GinkgoWriter
		log = logrus.NewEntry(logger)
		auth = &Authorizer{log: log, site: "ginkgo"}

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

		for r := 1; r <= 5; r++ {
			policy := readFixture(fmt.Sprintf("testdata/scenario%d.rego", r))
			fmt.Println(fmt.Sprintf("testdata/scenario%d.rego", r))
			claims = jwt.MapClaims(map[string]interface{}{
				"opa_policy": policy,
				"callerid": "up=bob",
			})

			allowed, err := auth.evaluatePolicy(req, policy, claims)
			Expect(err).ToNot(HaveOccurred())
			Expect(allowed).To(BeTrue())
		}
	})

	It("Should fail on all common scenarios", func() {
		policy := readFixture("testdata/scenario5.rego")
		claims = jwt.MapClaims(map[string]interface{}{
			"opa_policy": policy,
			"callerid": "up=bob",
		})

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
