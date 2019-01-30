package basicjwt

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	protocol "github.com/choria-io/go-protocol/protocol"
	"github.com/choria-io/go-protocol/protocol/v1"

	"github.com/choria-io/aaasvc/api/gen/models"
	auditors "github.com/choria-io/aaasvc/auditors"
	"github.com/choria-io/go-choria/choria"
	gomock "github.com/golang/mock/gomock"

	cconf "github.com/choria-io/go-choria/config"
	jwt "github.com/dgrijalva/jwt-go"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestWithGinkgo(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Signer/BasicJWT")
}

var _ = Describe("BasicJWT", func() {
	var (
		signer     *BasicJWT
		fw         *choria.Framework
		err        error
		mockctl    *gomock.Controller
		auditor    *MockAuditor
		authorizer *MockAuthorizer
		req        *models.SignRequest
		token      string
	)

	BeforeEach(func() {
		mockctl = gomock.NewController(GinkgoT())
		auditor = NewMockAuditor(mockctl)
		authorizer = NewMockAuthorizer(mockctl)

		fw, err = choria.NewWithConfig(cconf.NewConfigForTests())
		Expect(err).ToNot(HaveOccurred())
		signer, err = New(fw, &SignerConfig{SigningPubKey: "testdata/cert.pem"}, "ginkgo")
		Expect(err).ToNot(HaveOccurred())

		signer.SetAuthorizer(authorizer)
		signer.SetAuditors(auditor)
		protocol.Secure = "false"
		token = genToken()
		req = &models.SignRequest{Token: token}
	})

	AfterEach(func() {
		mockctl.Finish()
	})

	Describe("Sign", func() {
		var rpcreq protocol.Request
		var rpcreqstr string

		BeforeEach(func() {
			rpcreq, err = v1.NewRequest("ginkgo", "ginkgo.example.net", "choria=ginkgo", 60, "9b3a0089dbe0d896c1b79bbc12d61212", "mcollective")
			rpcreq.SetMessage("{}")
			Expect(err).ToNot(HaveOccurred())

			rpcreqstr, err = rpcreq.JSON()
			Expect(err).ToNot(HaveOccurred())
		})

		It("Should handle bad requests", func() {
			res := signer.Sign(req)
			Expect(res.Error).To(Equal("Could not parse request: Invalid request version '' expected choria:request:1"))
			Expect(res.SecureRequest).To(BeNil())
		})

		It("Should handle invalid JWT", func() {
			req.Token = ""
			req.Request = []byte(rpcreqstr)
			auditor.EXPECT().Audit(auditors.Deny, rpcreq.CallerID(), gomock.Any()).AnyTimes()
			res := signer.Sign(req)
			Expect(res.Error).To(Equal("Could not parse token: token contains an invalid number of segments"))
			Expect(res.SecureRequest).To(BeNil())
		})

		It("Should handle failed authorizations", func() {
			req.Request = []byte(rpcreqstr)
			auditor.EXPECT().Audit(auditors.Deny, "ginkgo=test", gomock.Any()).AnyTimes()
			authorizer.EXPECT().Authorize(gomock.Any(), gomock.Any()).Return(false, fmt.Errorf("simulated failure"))
			res := signer.Sign(req)
			Expect(res.Error).To(Equal("Could not authorize request: simulated failure"))
			Expect(res.SecureRequest).To(BeNil())
		})

		It("Should audit denied requests", func() {
			req.Request = []byte(rpcreqstr)
			auditor.EXPECT().Audit(auditors.Deny, "ginkgo=test", gomock.Any()).AnyTimes()
			authorizer.EXPECT().Authorize(gomock.Any(), gomock.Any()).Return(false, nil)
			res := signer.Sign(req)
			Expect(res.Error).To(Equal("Not allowed to perform request"))
			Expect(res.SecureRequest).To(BeNil())
		})

		It("Should create a valid SR", func() {
			req.Request = []byte(rpcreqstr)
			auditor.EXPECT().Audit(auditors.Allow, "ginkgo=test", gomock.Any()).AnyTimes()
			authorizer.EXPECT().Authorize(gomock.Any(), gomock.Any()).Return(true, nil)
			res := signer.Sign(req)
			Expect(res.Error).To(Equal(""))

			sr, err := fw.NewSecureRequest(rpcreq)
			Expect(err).ToNot(HaveOccurred())

			err = json.Unmarshal(res.SecureRequest, &sr)
			Expect(err).ToNot(HaveOccurred())
		})
	})
})

func genToken() string {
	token := jwt.NewWithClaims(jwt.GetSigningMethod("RS512"), jwt.MapClaims{
		"exp":      time.Now().UTC().Add(time.Hour).Unix(),
		"agents":   []string{"*"},
		"callerid": "ginkgo=test",
	})

	signKey, err := signKey("testdata/key.pem")
	Expect(err).ToNot(HaveOccurred())

	signed, err := token.SignedString(signKey)
	Expect(err).ToNot(HaveOccurred())

	return signed
}

func signKey(key string) (*rsa.PrivateKey, error) {
	pkeyBytes, err := ioutil.ReadFile(key)
	if err != nil {
		return nil, err
	}

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(pkeyBytes)
	if err != nil {
		return nil, err
	}

	return signKey, nil
}
