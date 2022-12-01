+++
title = "Org Issuer Based"
toc = true
weight = 20
pre = "<b>2.2. </b>"
+++

## Overview

This deployment method is suitable to users who do not have access to a Certificate Authority.  You might be a Puppet user but do not want to use the Puppet CA for multiple purposes or, you deployed using a non-Puppet method and so do not have easy access to a natively supported CA.

This mode completely removes the need for per-user x509 certificates, the entire system is controlled by a series of JWT tokens and ed25519 keys. The resulting system is a hybrid system where authentication is handled by AAA Service but Signing is optional and something the AAA Service has full control over.

{{% notice secondary "Version Hint" code-branch %}}
This applies only to Choria 0.27.0 and newer which is due to ship early 2023
{{% /notice %}}

The system is made up of a few components:

1. An Authentication service, called the **Authenticator**, accessed over HTTP(S), can be run anywhere
2. A Signing service, called the **Signer**, accessed over Choria RPC, must run in the datacenter where fleets are
3. An Authorization service, called the **Authorizer**, called by the Signer and ran in the same process
4. Optional audit logging, called **Auditors**, called by the Authorizers and ran in the same process

## Requirements

You must already have a Choria Organization Issuer, essentially a ed25519 key-pair, and you need access to issue new tokens using the Issuer.

The Organization Issuer can be made using `choria jwt keys` or using Hashicorp Vault Transit Secrets Engine.

### Issuer Public Key

Obtain your Organization Issuer public key, for the purpose of this documentation we will use `514969e316eb4a7146b8066feb6af5dbc05da0965ec57c9d3a7d3299d5d98fec`.

We'll assume the Issuer seed is in `choria-issuer.seed`.

{{% notice secondary "Using with Hashicorp Vault" info-circle %}}
If you are using Vault with the Transit Secrets Engine to store your Organization Issuer set the `VAULT_ADDR` and `VAULT_TOKEN` environment variables and add `--vault` to `choria jwt` commands that need the issuer. Use the key name instead of `choria-issuer.seed` in the examples.
{{% /notice %}}


### Authenticator JWT

You need to have a Choria Client JWT that is signed by the Organization Issuer and is a valid Chain Issuer.

First we create the ed25519 key pair that is unique to the Authenticator:

```nohighlight
$ choria jwt keys /etc/aaasvc/authenticator.seed /etc/aaasvc/authenticator.public
Public Key: d19ebddf1e3b41233e776c64c5dfe54861d868101c0ec27105ccead00234abef
```

Now create the JWT, signed by the Issuer:

```nohighlight
$ choria jwt client /etc/aaasvc/authenticator.jwt aaa_chain_delegator choria-issuer.seed \
     --public-key $(cat /etc/aaasvc/authenticator.public) \
     --issuer \               # It can issue clients
     --no-fleet-management \  # It can not access any fleet nodes over RPC
     --validity 365d          # It will expire after 1 year
```

### Request Signer JWT

You need to have a Choria Client JWT that will be used to sign requests on behalf of other users.

First we create the ed25519 key pair that is unique to the Signer:

```nohighlight
$ choria jwt keys /etc/aaasvc/signer.seed /etc/aaasvc/signer.public
Public Key: 7b692d69af281772d7bf98e228451974776b4208608c4a17bb6eebf335ef5142
```

Now create the JWT, signed by the Issuer:

```nohighlight
$ choria jwt client /etc/aaasvc/signer.jwt aaa_request_signer choria-issuer.seed \
     --public-key $(cat /etc/aaasvc/signer.public) \
     --no-fleet-management \  # It can not access any fleet nodes over RPC
     --auth-delegation \      # It can sign requests on behalf of others
     --validity 365d          # It will expire after 1 year
```

### RPC Service JWT

You need to have a Choria Server JWT that will be used by the RPC Service that signs requests for other users.

First we create the ed25519 key pair that is unique to the Signer Service:

```nohighlight
$ choria jwt keys /etc/aaasvc/signer-rpc.seed /etc/aaasvc/signer-rpc.public
Public Key: d3e0cdf8afc4b827953b3a0c3b01cf80618756d150d1d1e1f70017483a9b4cef
```

Now create the JWT, signed by the Issuer, replace `aaa.example.net` with an appropriately descriptive name for your environment, like the FQDN hosting the service:

```nohighlight
$ choria jwt server /etc/aaasvc/signer-rpc.jwt aaa.example.net $(cat /etc/aaasvc/signer-rpc.public) choria-issuer.seed
     --org choria \           # Must be `choria` for now
     --collectives choria \   # Add any other sub collectives you might have
     --service                # It's allowed to host Choria Services on the network
```

## General Service Configuration

The AAA Service is configured using a JSON file, here is a basic one showing common parts, the following documentation sections will add to this starter JSON file.

```json
{
  "logfile": "/var/log/aaasvc.log",
  "loglevel": "warn",
  "site": "london"
}
```

| Item       | Description                                                                                                     |
|------------|-----------------------------------------------------------------------------------------------------------------|
| `logfile`  | A file to log to, this is the standard location which will be covered by the included logrotation configuration |
| `loglevel` | The logging level, one of `debug`, `info`, `warn`, `error` or `fatal`                                           |
| `site`     | A site name to expose in statistics, logs, audits etc, typically a DC name or some unique location identifier   |

## Authenticator

Users log into Choria using `choria login` which communicates with the Authenticator service.  We have one Authenticator today called [userlist](../userlist) with its own documentation section.

Configuration only requires the private key for signing tokens:


```json
{
  "logfile": "/var/log/aaasvc.log",
  "loglevel": "warn",
  "site": "london",
  "port": "443",
  "tls_certificate": "/etc/aaasvc/ssl/https.pem",
  "tls_key": "/etc/aaasvc/ssl/https.key",
  "tls_ca":  "/etc/aaasvc/ssl/https-ca.pem",
  "authenticator": "userlist",
  "userlist_authenticator": {
    "validity": "1h",
    "signing_key": "/etc/aaasvc/authenticator.seed",
    "signing_token": "/etc/aaasvc/authenticator.public",
    "users": [],
    "users_file": ""
  }
}
```

Here we set the additional key `signing_token`.

## Signer

The Signer listens on the Choria RPC network for RPC clients wishing to have their requests signed, signs them and sends the signed request back.

The service is scalable horizontally or vertically, you can simply run many instances at the same time, there is no shared state between them or any kind of leader election, it's all Active-Active and adding more instances adds more capacity.

### Choria Configuration

Because the signer connects to Choria it needs a configuration file. Store this in `/etc/aaasvc/choria.conf`

```ini
plugin.security.provider = choria
plugin.security.choria.seed_file = /etc/aaasvc/signer-rpc.seed
plugin.security.choria.token_file = /etc/aaasvc/signer-rpc.jwt
plugin.choria.middleware_hosts = choria.example.net:4222
identity = aaa.example.net
logfile = /var/log/choria/choria-aaa.example.net.log
```

### Signer Configuration

The configuration of the signer has a few relevant items, here's a full configuration for this scenario:

```json
{
  "choria_config": "/etc/aaasvc/choria.conf",
  "logfile": "/var/log/aaasvc.log",
  "loglevel": "warn",
  "site": "london",
  "signer": "basicjwt",
  "basicjwt_signer": {
    "signing_certificate": "/etc/aaasvc/authenticator.public",
    "signing_token": "/etc/aaasvc/signer.jwt",
    "signing_seed": "/etc/aaasvc/signer.seed",
    "max_validity":"1h",
    "choria_service": true
  }
}
```

| Property              | Description                                                                                                                                         |
|-----------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|
| `signing_certificate` | The public key for your Authenticator. Incoming signing requests will have their JWTs verified using this, only ones signed by it will be allowed   |
| `signing_token`       | The token used to sign user requests                                                                                                                |
| `signing_seed`        | The token used to sign user requests                                                                                                                |
| `max_validity`        | Enforces the maximum validity period on any JWT we accept. The only exception is for tokens with the `service` claim set to true                    |
| `choria_service`      | Instructs the Signer to connect to Choria and start a service, otherwise HTTPS must be used to sign requests, strongly recommend to use this method |

## Authorizer

There are 2 Authorizers and a given signer server can run only one.

### Action List

The Action List Authorizer reads the `acls` claim from the users JWT and evaluate the request being signed against the list of allowed actions.


| ACL                                  | Description                                                                            |
|--------------------------------------|----------------------------------------------------------------------------------------|
| `["puppet.status", "puppet.enable"]` | User can access just these 2 actions and no others                                     |
| `["puppet.*", "rpcutil.ping"]`       | User can access all actions under the `puppet` agent and one under the `rpcutil` agent |
| `["*"]`                              | User can perform all actions on all agents                                             |

Configuration is easy, it has no specific configuration.:

```json
{
  "logfile": "/var/log/aaasvc.log",
  "loglevel": "warn",
  "site": "london",
  "authorizer": "actionlist"
}
```

### Open Policy Agent

Requests can be authorized using [Open Policy Agent](https://www.openpolicyagent.org/), it's a large topic and has it's own [documentation section](../opa/).

## Auditing

Auditors will write a log of every Authorization decision to their configured destination, multiple auditors can be active at a time.

### Logfile

This is a simple auditor that just writes a logfile of the actions taken.

```json
{
  "logfile": "/var/log/aaasvc.log",
  "loglevel": "warn",
  "site": "london",
  "auditors": ["logfile"],
  "logfile_auditor": {
    "logfile": "/var/log/signer_audit.json"
  }
}
```

You have to arrange for rotation of this log file, each line will be a JSON line.

### Choria Streams

If you want to aggregate audit logs from your regional signers back to the central authentication service this is the auditor to use.

It publishes structured messages to a Choria Streams topic that you can use the [Choria Stream Replicator](https://github.com/choria-io/stream-replicator) to transport these from your regional DC to central for consumption.

Published messages will match the [io.choria.signer.v1.signature_audit](https://choria.io/schemas/choria/signer/v1/signature_audit.json) JSON Schema.

```json
{
  "logfile": "/var/log/aaasvc.log",
  "loglevel": "warn",
  "site": "london",
  "auditors": ["jetstream"],
  "jetstream_auditor": {
    "cluster_id": "test-cluster",
    "servers": "nats://localhost:4222",
    "topic": "audit"
  }
}
```

## Choria Broker Configuration

The Broker will verify connections are signed by anyone the Organization Issuer signed

```ini
plugin.security.issuer.names = choria
plugin.security.issuer.choria.public = 514969e316eb4a7146b8066feb6af5dbc05da0965ec57c9d3a7d3299d5d98fec
```

## Choria Client Configuration

Clients must know to login and requests signing be done, the `client.conf` settings enable that:

### Choria Network Based Signatures

```ini
plugin.security.provider = choria
plugin.security.choria.token_file = ~/.choria/client.jwt
plugin.security.choria.seed_file = ~/.choria/client.key
plugin.choria.security.request_signer.service = true
plugin.login.aaasvc.login.url = https://caaa.example.net/choria/v1/login
```

## Choria Server Configuration

The Server will verify requests are signed by anyone the Organization Issuer signed

```ini
plugin.security.issuer.names = choria
plugin.security.issuer.choria.public = 514969e316eb4a7146b8066feb6af5dbc05da0965ec57c9d3a7d3299d5d98fec
```

## Full Sample Configuration

Here is a sample configuration with:

* Authenticator on port 433 with external users
* Signer listening as a service
* Open Policy Agent Authorizer
* Logfile auditing

```json
{
  "logfile": "/var/log/aaasvc.log",
  "loglevel": "warn",
  "site": "london",
  "port": "443",
  "tls_certificate": "/etc/aaasvc/ssl/https.pem",
  "tls_key": "/etc/aaasvc/ssl/https.key",
  "tls_ca":  "/etc/aaasvc/ssl/https-ca.pem",
  "authenticator": "userlist",
  "authorizer": "opa",
  "auditors": ["logfile"],
  "signer": "basicjwt",
  "basicjwt_signer": {
    "signing_certificate": "/etc/aaasvc/authenticator.public",
    "signing_token": "/etc/aaasvc/signer.jwt",
    "signing_seed": "/etc/aaasvc/signer.seed",
    "max_validity":"1h",
    "choria_service": true
  }
  "logfile_auditor": {
    "logfile": "/var/log/signer_audit.json"
  },
  "userlist_authenticator": {
    "validity": "1h",
    "signing_key": "/etc/aaasvc/authenticator.seed",
    "signing_token": "/etc/aaasvc/authenticator.public",
    "users_file": "/etc/aaasvc/users.json"
  }
}
```
