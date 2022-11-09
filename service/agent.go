package service

import (
	"context"

	"github.com/choria-io/aaasvc/signers"
	"github.com/choria-io/go-choria/inter"
	"github.com/choria-io/go-choria/providers/agent/mcorpc"
	"github.com/choria-io/go-choria/server/agents"
	"github.com/sirupsen/logrus"
)

type SignRPCRequest struct {
	Request   string `json:"request"`
	Token     string `json:"token"`
	Signature string `json:"signature"`
}

type SignRPCResponse struct {
	SecureRequest string `json:"secure_request"`
}

var metadata = &agents.Metadata{
	Name:        "aaa_signer",
	License:     "Apache-2.0",
	Author:      "R.I.Pienaar <rip@devco.net>",
	Timeout:     10,
	URL:         "https://github.com/choria-io/aaasvc",
	Description: "Request Signer for Choria AAA Service",
	Service:     true,
}

func NewService(fw mcorpc.ChoriaFramework, version string, log *logrus.Entry) (agents.Agent, error) {
	metadata.Version = version
	agent := mcorpc.New(metadata.Name, metadata, fw, log)

	agent.MustRegisterAction("sign", signAction)

	return agent, nil
}

func signAction(ctx context.Context, req *mcorpc.Request, reply *mcorpc.Reply, agent *mcorpc.Agent, conn inter.ConnectorInfo) {
	input := SignRPCRequest{}
	if !mcorpc.ParseRequestData(&input, req, reply) {
		return
	}

	output := &SignRPCResponse{}
	reply.Data = output

	allowed, signed, err := signers.SignRequest([]byte(input.Request), input.Token, input.Signature)
	switch {
	case !allowed && err == nil:
		reply.Statusmsg = "Request Denied"
		reply.Statuscode = mcorpc.Aborted

	case err != nil:
		agent.Log.Errorf("Signing request %s from %s failed: %s", req.RequestID, req.CallerID, err)
		reply.Statusmsg = "Request Denied"
		reply.Statuscode = mcorpc.Aborted

	case allowed:
		output.SecureRequest = string(signed)
	}
}
