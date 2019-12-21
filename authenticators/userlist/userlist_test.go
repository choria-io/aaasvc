package userlist

import (
	"crypto/rsa"
	"io/ioutil"
	"testing"

	jwt "github.com/dgrijalva/jwt-go"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/choria-io/aaasvc/api/gen/models"
	"github.com/sirupsen/logrus"
)

func TestWithGinkgo(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Authenticators/Userlist")
}

var _ = Describe("Authenticators/Userlist", func() {
	var (
		conf *AuthenticatorConfig
		req  *models.LoginRequest
		auth *Authenticator
		err  error
		log  *logrus.Entry
	)

	BeforeEach(func() {
		conf = &AuthenticatorConfig{
			SigningKey:    "testdata/key.pem",
			TokenValidity: "1h",
			Users: []*User{
				&User{
					Username: "bob",
					Password: "$2a$06$chB5d2pCKEzM6xlDoPvofuKW52piJ5f8fGvxHPTDaeSJOSNY76yai",
					ACLs:     []string{"*"},
					OPAPolicyFile: "testdata/test.rego",
					Properties: map[string]string{"group":"admins"},
				},
			},
		}

		logger := logrus.New()
		logger.Out = ioutil.Discard
		log = logrus.NewEntry(logger)
		req = &models.LoginRequest{}
		auth, err = New(conf, log, "ginkgo")
		Expect(err).ToNot(HaveOccurred())
	})

	Describe("New", func() {
		It("Should parse the duration", func() {
			_, err := New(&AuthenticatorConfig{
				TokenValidity: "1y",
			}, log, "ginkgo")
			Expect(err).To(MatchError("invalid token validity: time: unknown unit y in duration 1y"))

			_, err = New(&AuthenticatorConfig{
				TokenValidity: "1h",
			}, log, "ginkgo")
			Expect(err).ToNot(HaveOccurred())
		})
	})

	Describe("Login", func() {
		It("Should handle invalid users", func() {
			req.Username = "invalid"
			res := auth.Login(req)
			Expect(res.Error).To(Equal("Login failed"))
		})

		It("Should handle invalid password", func() {
			req.Username = "bob"
			req.Password = "fooo"
			res := auth.Login(req)
			Expect(res.Error).To(Equal("Login failed"))
		})

		It("Should generate correct claims", func() {
			req.Username = "bob"
			req.Password = "secret"
			res := auth.Login(req)
			Expect(res.Error).To(Equal(""))

			pub, err := signKey()
			Expect(err).ToNot(HaveOccurred())

			token, err := jwt.Parse(res.Token, func(token *jwt.Token) (interface{}, error) {
				return pub, nil
			})
			Expect(err).ToNot(HaveOccurred())

			claims, ok := token.Claims.(jwt.MapClaims)
			Expect(ok).To(BeTrue())

			caller, ok := claims["callerid"].(string)
			Expect(ok).To(BeTrue())
			Expect(caller).To(Equal("up=bob"))

			agents, ok := claims["agents"].([]interface{})
			Expect(ok).To(BeTrue())
			Expect(agents).To(HaveLen(1))
			Expect(agents[0].(string)).To(Equal("*"))

			policy, ok := claims["opa_policy"].(string)
			Expect(ok).To(BeTrue())
			Expect(policy).To(Equal(readFixture("testdata/test.rego")))

			props, ok := claims["user_properties"].(map[string]interface{})
			Expect(ok).To(BeTrue())
			group, ok := props["group"].(string)
			Expect(ok).To(BeTrue())
			Expect(group).To(Equal("admins"))
		})
	})
})

func readFixture(f string) string {
	c, err := ioutil.ReadFile(f)
	if err != nil {
		panic(err)
	}

	return string(c)
}

func signKey() (*rsa.PublicKey, error) {
	certBytes, err := ioutil.ReadFile("testdata/cert.pem")
	if err != nil {
		return nil, err
	}

	signKey, err := jwt.ParseRSAPublicKeyFromPEM(certBytes)
	if err != nil {
		return nil, err
	}

	return signKey, nil
}
