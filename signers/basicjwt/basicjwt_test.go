package basicjwt

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/choria-io/go-choria/protocol"
	v1 "github.com/choria-io/go-choria/protocol/v1"
	"github.com/choria-io/go-choria/tokens"
	"golang.org/x/crypto/ed25519"

	"github.com/choria-io/aaasvc/api/gen/models"
	"github.com/choria-io/aaasvc/auditors"
	"github.com/choria-io/go-choria/choria"
	"github.com/golang/mock/gomock"

	cconf "github.com/choria-io/go-choria/config"

	. "github.com/onsi/ginkgo/v2"
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
		pubK       ed25519.PublicKey
		priK       ed25519.PrivateKey
		token      string
	)

	BeforeEach(func() {
		mockctl = gomock.NewController(GinkgoT())
		auditor = NewMockAuditor(mockctl)
		authorizer = NewMockAuthorizer(mockctl)

		pubK, priK, err = choria.Ed25519KeyPair()
		Expect(err).ToNot(HaveOccurred())

		cfg := cconf.NewConfigForTests()
		cfg.DisableSecurityProviderVerify = true

		fw, err = choria.NewWithConfig(cfg)
		Expect(err).ToNot(HaveOccurred())
		signer, err = New(fw, &SignerConfig{SigningPubKey: "testdata/cert.pem", MaxValidity: "1h"}, "ginkgo")
		Expect(err).ToNot(HaveOccurred())

		signer.SetAuthorizer(authorizer)
		signer.SetAuditors(auditor)

		protocol.Secure = "false"
		token = genToken(time.Hour, pubK)
		req = &models.SignRequest{Token: token}
	})

	AfterEach(func() {
		mockctl.Finish()
	})

	Describe("Sign", func() {
		var rpcreq protocol.Request
		var rpcreqstr []byte

		BeforeEach(func() {
			rpcreq, err = v1.NewRequest("ginkgo", "ginkgo.example.net", "choria=ginkgo", 60, "9b3a0089dbe0d896c1b79bbc12d61212", "mcollective")
			rpcreq.SetMessage([]byte("{}"))
			Expect(err).ToNot(HaveOccurred())

			rpcreqstr, err = rpcreq.JSON()
			Expect(err).ToNot(HaveOccurred())
		})

		It("Should handle bad requests", func() {
			res := signer.Sign(req)
			Expect(res.Error).To(Equal("Request denied"))
			Expect(res.Detail).To(Equal("invalid request: unsupported request version 'io.choria.protocol.unknown'"))
			Expect(res.SecureRequest).To(BeNil())
		})

		It("Should handle invalid JWT", func() {
			req.Token = ""
			req.Request = rpcreqstr
			auditor.EXPECT().Audit(auditors.Deny, rpcreq.CallerID(), gomock.Any()).AnyTimes()
			res := signer.Sign(req)
			Expect(res.Error).To(Equal("Request denied"))
			Expect(res.Detail).To(Equal("invalid token: could not parse client id token: token contains an invalid number of segments"))
			Expect(res.SecureRequest).To(BeNil())
		})

		It("Should handle JWT that expire too far in the future", func() {
			req.Token = genToken(10*time.Hour, pubK)
			req.Request = rpcreqstr
			auditor.EXPECT().Audit(auditors.Deny, rpcreq.CallerID(), gomock.Any()).AnyTimes()
			res := signer.Sign(req)
			Expect(res.Error).To(Equal("Request denied"))
			Expect(res.Detail).To(Equal("invalid token: invalid claims: expiry is not set or it is too far in the future"))
			Expect(res.SecureRequest).To(BeNil())
		})

		It("Should handle JWT without an exp claim", func() {
			req.Token = genToken(0, pubK)
			req.Request = rpcreqstr
			auditor.EXPECT().Audit(auditors.Deny, rpcreq.CallerID(), gomock.Any()).AnyTimes()
			res := signer.Sign(req)
			Expect(res.Error).To(Equal("Request denied"))
			Expect(res.Detail).To(Equal("invalid token: invalid claims: expiry is not set or it is too far in the future"))
			Expect(res.SecureRequest).To(BeNil())
		})

		It("Should handle invalid signatures", func() {
			// first a totally bogus sig
			req.Token = genToken(time.Minute, pubK)
			req.Request = rpcreqstr
			req.Signature = "invalid"
			auditor.EXPECT().Audit(auditors.Deny, rpcreq.CallerID(), gomock.Any()).AnyTimes()
			res := signer.Sign(req)
			Expect(res.Error).To(Equal("Request denied"))
			Expect(res.Detail).To(Equal("invalid signature: invalid signature in request: encoding/hex: invalid byte: U+0069 'i'"))
			Expect(res.SecureRequest).To(BeNil())

			// now a valid sig but for a different message
			sig, err := choria.Ed25519Sign(priK, []byte("invalid message"))
			Expect(err).ToNot(HaveOccurred())
			req.Signature = hex.EncodeToString(sig)
			res = signer.Sign(req)
			Expect(res.Error).To(Equal("Request denied"))
			Expect(res.Detail).To(Equal("invalid signature: invalid request signature"))
			Expect(res.SecureRequest).To(BeNil())
		})

		It("Should handle failed authorizations", func() {
			req.Request = rpcreqstr
			req.Token = genToken(time.Minute, pubK)

			signer.allowBearerTokens = true

			auditor.EXPECT().Audit(auditors.Deny, "ginkgo=test_example_net", gomock.Any()).AnyTimes()
			authorizer.EXPECT().Authorize(gomock.Any(), gomock.Any()).Return(false, fmt.Errorf("simulated failure"))
			res := signer.Sign(req)
			Expect(res.Error).To(Equal("Request denied"))
			Expect(res.Detail).To(Equal("authorization failed: simulated failure"))
			Expect(res.SecureRequest).To(BeNil())
		})

		It("Should audit denied requests", func() {
			signer.allowBearerTokens = true

			req.Request = rpcreqstr
			auditor.EXPECT().Audit(auditors.Deny, "ginkgo=test_example_net", gomock.Any()).AnyTimes()
			authorizer.EXPECT().Authorize(gomock.Any(), gomock.Any()).Return(false, nil)
			res := signer.Sign(req)
			Expect(res.Error).To(Equal("Request denied"))
			Expect(res.Detail).To(Equal(""))
			Expect(res.SecureRequest).To(BeNil())
		})

		It("Should create a valid SR", func() {
			req.Request = rpcreqstr

			// make sure we expect a signature
			signer.allowBearerTokens = false
			sig, err := choria.Ed25519Sign(priK, req.Request)
			Expect(err).ToNot(HaveOccurred())
			req.Signature = hex.EncodeToString(sig)

			auditor.EXPECT().Audit(auditors.Allow, "ginkgo=test_example_net", gomock.Any()).AnyTimes()
			authorizer.EXPECT().Authorize(gomock.Any(), gomock.Any()).Return(true, nil)
			res := signer.Sign(req)
			Expect(res.Error).To(Equal(""))
			Expect(res.Detail).To(Equal(""))

			sr, err := fw.NewSecureRequest(rpcreq)
			Expect(err).ToNot(HaveOccurred())

			err = json.Unmarshal(res.SecureRequest, &sr)
			Expect(err).ToNot(HaveOccurred())
		})
	})
})

func genToken(exp time.Duration, pubK ed25519.PublicKey) string {
	claims, err := tokens.NewClientIDClaims("ginkgo=test@example.net", []string{"*"}, "choria", nil, "", "", exp, nil, pubK)
	Expect(err).ToNot(HaveOccurred())
	signed, err := tokens.SignTokenWithKeyFile(claims, "testdata/key.pem")
	Expect(err).ToNot(HaveOccurred())
	return signed
}
