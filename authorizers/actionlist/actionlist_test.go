package actionlist

import (
	"io/ioutil"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/choria-io/go-protocol/protocol/v1"
	jwt "github.com/dgrijalva/jwt-go"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestWithGinkgo(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Authorizers/Actionlist")
}

var _ = Describe("Authorizers/Actionlist", func() {
	var auth Authorizer
	var log *logrus.Entry

	BeforeEach(func() {
		logger := logrus.New()
		logger.Out = ioutil.Discard
		log = logrus.NewEntry(logger)

		auth = Authorizer{log: log, site: "ginkgo"}
	})

	Describe("Authorize", func() {
		It("Should always allow discovery agent", func() {
			claims := jwt.MapClaims{}
			req, err := v1.NewRequest("discovery", "ginkgo.example.net", "choria=ginkgo", 60, "123454", "mcollective")
			Expect(err).ToNot(HaveOccurred())

			allowed, err := auth.Authorize(req, claims)
			Expect(err).ToNot(HaveOccurred())
			Expect(allowed).To(BeTrue())
		})

		It("Should fail disallowed requests", func() {
			claims := jwt.MapClaims{
				"agents": []interface{}{"nothing"},
			}

			req, err := v1.NewRequest("rpcutil", "ginkgo.example.net", "choria=ginkgo", 60, "123454", "mcollective")
			Expect(err).ToNot(HaveOccurred())
			req.SetMessage(`{"action":"ping", "agent":"rpcutil"}`)

			allowed, err := auth.Authorize(req, claims)
			Expect(err).ToNot(HaveOccurred())
			Expect(allowed).To(BeFalse())
		})
	})

	Describe("validateAction", func() {
		It("Should detect invalid agent claims", func() {
			claims := jwt.MapClaims{
				"agents": "invalid",
			}

			ok, err := validateAction("agent", "action", claims, log)
			Expect(err).To(MatchError("Invalid agent claims"))
			Expect(ok).To(BeFalse())
		})

		It("Should support '*' agents", func() {
			claims := jwt.MapClaims{
				"agents": []interface{}{"*"},
			}

			ok, err := validateAction("agent", "action", claims, log)
			Expect(ok).To(BeTrue())
			Expect(err).ToNot(HaveOccurred())
		})

		It("Should support action wildcards", func() {
			claims := jwt.MapClaims{
				"agents": []interface{}{"rpcutil.*"},
			}

			ok, err := validateAction("rpcutil", "action", claims, log)
			Expect(ok).To(BeTrue())
			Expect(err).ToNot(HaveOccurred())

			ok, err = validateAction("other", "action", claims, log)
			Expect(ok).To(BeFalse())
		})

		It("Should support specific agent.action", func() {
			claims := jwt.MapClaims{
				"agents": []interface{}{"rpcutil.ping"},
			}

			ok, err := validateAction("rpcutil", "ping", claims, log)
			Expect(ok).To(BeTrue())
			Expect(err).ToNot(HaveOccurred())

			ok, err = validateAction("rpcutil", "other", claims, log)
			Expect(ok).To(BeFalse())

			ok, err = validateAction("other", "action", claims, log)
			Expect(ok).To(BeFalse())
		})
	})
})
