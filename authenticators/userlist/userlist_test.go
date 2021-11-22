package userlist

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/choria-io/aaasvc/api/gen/models"
	"github.com/choria-io/go-choria/choria"
	"github.com/choria-io/go-choria/tokens"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ed25519"
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
		pubK ed25519.PublicKey
		priK ed25519.PrivateKey
	)

	BeforeEach(func() {
		conf = &AuthenticatorConfig{
			SigningKey:    "testdata/key.pem",
			TokenValidity: "1h",
			Users: []*User{
				&User{
					Username:      "bob",
					Password:      "$2a$06$chB5d2pCKEzM6xlDoPvofuKW52piJ5f8fGvxHPTDaeSJOSNY76yai",
					ACLs:          []string{"*"},
					OPAPolicyFile: "testdata/test.rego",
					Properties:    map[string]string{"group": "admins"},
				},
			},
		}

		pubK, priK, err = choria.Ed25519KeyPair()
		logger := logrus.New()
		logger.Out = GinkgoWriter
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
			Expect(err).To(MatchError("invalid token validity: time: unknown unit \"y\" in duration \"1y\""))

			_, err = New(&AuthenticatorConfig{
				TokenValidity: "1h",
			}, log, "ginkgo")
			Expect(err).ToNot(HaveOccurred())
		})
	})

	Describe("reloadUserFile", func() {
		It("Should handle no file specified", func() {
			conf.UsersFile = ""
			read, err := auth.reloadUserFile()
			Expect(err).ToNot(HaveOccurred())
			Expect(read).To(BeFalse())
		})

		It("Should read a file and not reread it again if not needed", func() {
			conf.UsersFile = "testdata/users.json"
			read, err := auth.reloadUserFile()
			Expect(err).ToNot(HaveOccurred())
			Expect(read).To(BeTrue())

			Expect(auth.c.Users[0].Username).To(Equal("from_file"))

			read, err = auth.reloadUserFile()
			Expect(err).ToNot(HaveOccurred())
			Expect(read).To(BeFalse())
		})

		It("Should reread a file when needed", func() {
			conf.UsersFile = "testdata/users.json"
			read, err := auth.reloadUserFile()
			Expect(err).ToNot(HaveOccurred())
			Expect(read).To(BeTrue())
			Expect(auth.c.Users[0].Username).To(Equal("from_file"))

			now := time.Now()
			err = os.Chtimes("testdata/users.json", now, now)
			Expect(err).ToNot(HaveOccurred())

			read, err = auth.reloadUserFile()
			Expect(err).ToNot(HaveOccurred())
			Expect(read).To(BeTrue())
			Expect(auth.c.Users[0].Username).To(Equal("from_file"))

			read, err = auth.reloadUserFile()
			Expect(err).ToNot(HaveOccurred())
			Expect(read).To(BeFalse())
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

		It("Should fail for requests from the future", func() {
			req.Username = "bob"
			req.Password = "secret"
			req.PublicKey = hex.EncodeToString(pubK)
			req.Timestamp = strconv.Itoa(int(time.Now().Add(time.Hour).Unix()))

			sig, err := choria.Ed25519Sign(priK, []byte(fmt.Sprintf("%s:%s:%s", req.Timestamp, req.Username, req.Password)))
			Expect(err).ToNot(HaveOccurred())
			req.Signature = hex.EncodeToString(sig)

			res := auth.Login(req)
			Expect(res.Error).To(Equal("Login failed"))
			Expect(res.Detail).To(Equal("future request"))
		})

		It("Should fail for requests too far ago", func() {
			req.Username = "bob"
			req.Password = "secret"
			req.PublicKey = hex.EncodeToString(pubK)
			req.Timestamp = strconv.Itoa(int(time.Now().Add(-2 * time.Minute).Unix()))

			sig, err := choria.Ed25519Sign(priK, []byte(fmt.Sprintf("%s:%s:%s", req.Timestamp, req.Username, req.Password)))
			Expect(err).ToNot(HaveOccurred())
			req.Signature = hex.EncodeToString(sig)

			res := auth.Login(req)
			Expect(res.Error).To(Equal("Login failed"))
			Expect(res.Detail).To(Equal("old request"))
		})

		It("Should fail for invalid signatures", func() {
			req.Username = "bob"
			req.Password = "secret"
			req.PublicKey = hex.EncodeToString(pubK)
			req.Timestamp = strconv.Itoa(int(time.Now().Unix()))

			sig, err := choria.Ed25519Sign(priK, []byte(fmt.Sprintf("%s:%s", req.Username, req.Password)))
			Expect(err).ToNot(HaveOccurred())
			req.Signature = hex.EncodeToString(sig)

			res := auth.Login(req)
			Expect(res.Error).To(Equal("Login failed"))
			Expect(res.Detail).To(Equal("invalid sig"))
		})

		It("Should generate correct claims", func() {
			req.Username = "bob"
			req.Password = "secret"
			req.PublicKey = hex.EncodeToString(pubK)
			req.Timestamp = strconv.Itoa(int(time.Now().Unix()))

			sig, err := choria.Ed25519Sign(priK, []byte(fmt.Sprintf("%s:%s:%s", req.Timestamp, req.Username, req.Password)))
			Expect(err).ToNot(HaveOccurred())
			req.Signature = hex.EncodeToString(sig)

			res := auth.Login(req)
			Expect(res.Error).To(Equal(""))

			claims, err := tokens.ParseClientIDTokenWithKeyfile(res.Token, "testdata/cert.pem", true)
			Expect(err).ToNot(HaveOccurred())

			Expect(claims.CallerID).To(Equal("up=bob"))
			Expect(claims.AllowedAgents).To(Equal([]string{"*"}))
			Expect(claims.OPAPolicy).To(Equal(readFixture("testdata/test.rego")))
			Expect(claims.Purpose).To(Equal(tokens.ClientIDPurpose))
			Expect(claims.PublicKey).To(Equal(hex.EncodeToString(pubK)))
			Expect(claims.UserProperties).To(Equal(map[string]string{
				"group": "admins",
			}))
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
