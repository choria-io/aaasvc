package basicjwt

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	"github.com/choria-io/go-choria/protocol"
	v1 "github.com/choria-io/go-choria/protocol/v1"

	"github.com/choria-io/aaasvc/api/gen/models"
	"github.com/choria-io/aaasvc/auditors"
	"github.com/choria-io/go-choria/choria"
	"github.com/golang/mock/gomock"

	cconf "github.com/choria-io/go-choria/config"
	"github.com/golang-jwt/jwt"

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

		cfg := cconf.NewConfigForTests()
		cfg.DisableSecurityProviderVerify = true

		fw, err = choria.NewWithConfig(cfg)
		Expect(err).ToNot(HaveOccurred())
		signer, err = New(fw, &SignerConfig{SigningPubKey: "testdata/cert.pem", MaxValidity: "1h"}, "ginkgo")
		Expect(err).ToNot(HaveOccurred())

		signer.SetAuthorizer(authorizer)
		signer.SetAuditors(auditor)

		protocol.Secure = "false"
		token = genToken(time.Now().UTC().Add(time.Hour).Unix())
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
			Expect(res.Error).To(Equal("Request denied"))
			Expect(res.SecureRequest).To(BeNil())
		})

		It("Should handle invalid JWT", func() {
			req.Token = ""
			req.Request = []byte(rpcreqstr)
			auditor.EXPECT().Audit(auditors.Deny, rpcreq.CallerID(), gomock.Any()).AnyTimes()
			res := signer.Sign(req)
			Expect(res.Error).To(Equal("Request denied"))
			Expect(res.SecureRequest).To(BeNil())
		})

		It("Should handle JWT that expire too far in the future", func() {
			req.Token = genToken(time.Now().UTC().Add(10 * time.Hour).Unix())
			req.Request = []byte(rpcreqstr)
			auditor.EXPECT().Audit(auditors.Deny, rpcreq.CallerID(), gomock.Any()).AnyTimes()
			res := signer.Sign(req)
			Expect(res.Error).To(Equal("Request denied"))
			Expect(res.SecureRequest).To(BeNil())
		})

		It("Should handle JWT without an exp claim", func() {
			req.Token = genToken(0)
			req.Request = []byte(rpcreqstr)
			auditor.EXPECT().Audit(auditors.Deny, rpcreq.CallerID(), gomock.Any()).AnyTimes()
			res := signer.Sign(req)
			Expect(res.Error).To(Equal("Request denied"))
			Expect(res.SecureRequest).To(BeNil())
		})

		It("Should handle failed authorizations", func() {
			req.Request = []byte(rpcreqstr)
			auditor.EXPECT().Audit(auditors.Deny, "ginkgo=test_example_net", gomock.Any()).AnyTimes()
			authorizer.EXPECT().Authorize(gomock.Any(), gomock.Any()).Return(false, fmt.Errorf("simulated failure"))
			res := signer.Sign(req)
			Expect(res.Error).To(Equal("Request denied"))
			Expect(res.SecureRequest).To(BeNil())
		})

		It("Should audit denied requests", func() {
			req.Request = []byte(rpcreqstr)
			auditor.EXPECT().Audit(auditors.Deny, "ginkgo=test_example_net", gomock.Any()).AnyTimes()
			authorizer.EXPECT().Authorize(gomock.Any(), gomock.Any()).Return(false, nil)
			res := signer.Sign(req)
			Expect(res.Error).To(Equal("Request denied"))
			Expect(res.SecureRequest).To(BeNil())
		})

		It("Should create a valid SR", func() {
			req.Request = []byte(rpcreqstr)
			auditor.EXPECT().Audit(auditors.Allow, "ginkgo=test_example_net", gomock.Any()).AnyTimes()
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

func genToken(exp int64) string {
	claims := jwt.MapClaims{
		"agents":   []string{"*"},
		"callerid": "ginkgo=test@example.net",
	}

	if exp > 0 {
		claims["exp"] = exp
	}

	token := jwt.NewWithClaims(jwt.GetSigningMethod("RS512"), claims)

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
