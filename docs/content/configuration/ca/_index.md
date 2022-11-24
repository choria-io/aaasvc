+++
title = "CA Based"
toc = true
weight = 10
pre = "<b>1.1. </b>"
+++

## Overview

This deployment method is suitable to the typical Puppet user who wish to bring a little centralization to their system. It uses certificates from the Puppet CA and you will need to make a number of extra ones.

This mode does not completely remove the need for per-user certificates, but, it will help a lot with multi node scenarios and allow you a more easy to manage method of managing RBAC.

The system is made up of a few components:

 1. An Authentication service, called the **Authenticator**, accessed over HTTP(S), can be run anywhere
 2. A Signing service, called the **Signer**, accessed over Choria RPC, must run in the datacenter where fleets are
 3. An Authorization service, called the **Authorizer**, called by the Signer and ran in the same process
 4. Optional audit logging, called **Auditors**, called by the Authorizers and ran in the same process

## Requirements

### Privileged Certificate

You need to obtain from your Certificate Authority a certificate named `<something>.privileged.mcollective`, if you are using Puppet you can do that with `choria enroll --certname aaasvc.privileged.mcollective`. Store the certificate in `/etc/aaasvc/ssl/aaasvc.privileged.mcollective.pem` and the key in `/etc/aaasvc/ssl/aaasvc.privileged.mcollective.key`, you also need the CA that signed it stored in `/etc/aaasvc/ssl/aaasvc.privileged.mcollective-ca.pem`.

### Signing Key-Pair

The JWT tokens will be signed using an RSA Key and needs to be generated.  It does not need to be signed by a CA.

```nohighlight
$ openssl genrsa -out /etc/aaasvc/jwt-signer.key 2048
$ openssl rsa -in /etc/aaasvc/signer-private.key -outform PEM -pubout -out /etc/aaasvc/jwt-signer.pem
```

### Certificate for HTTPS

The login service listens on HTTPS and so needs a certificate, key and certificate authority files. Generally these would be from the same Certificate Authority as your fleet nodes - probably Puppet.  Store them in `/etc/aaasvc/ssl/https.pem`, `/etc/aaasvc/ssl/https.key`, `/etc/aaasvc/ssl/https-ca.pem`.

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

For this deployment method the `authentication_delegator`, `service`, `signed_fleet_management` and `fleet_management` permissions do not apply.

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
    "signing_key": "/etc/aaasvc/signer-private.key",
    "users": [],
    "users_file": ""
  }
}
```

## Signer

The Signer listens on the Choria RPC network for RPC clients wishing to have their requests signed, signs them and sends the signed request back.

The service is scalable horizontally or vertically, you can simply run many instances at the same time, there is no shared state between them or any kind of leader election, it's all Active-Active and adding more instances adds more capacity.

### Choria Configuration

Because the signer connects to Choria it needs a configuration file. Store this in `/etc/aaasvc/choria.conf`

```ini
plugin.security.provider = file
plugin.security.file.certificate = /etc/aaasvc/ssl/aaasvc.privileged.mcollective.pem
plugin.security.file.key = /etc/aaasvc/ssl/aaasvc.privileged.mcollective.key
plugin.security.file.ca = /etc/aaasvc/ssl/aaasvc.privileged.mcollective-ca.pem
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
    "signing_certificate": "/etc/aaasvc/jwt-signer.pem",
    "max_validity":"2h",
    "choria_service": true,
    "allow_bearer_tokens": true
  }
}
```

| Property              | Description                                                                                                                                         |
|-----------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|
| `signing_certificate` | The public key for your Authenticator. Incoming signing requests will have their JWTs verified using this, only ones signed by it will be allowed   |
| `max_validity`        | Enforces the maximum validity period on any JWT we accept. The only exception is for tokens with the `service` claim set to true                    |
| `choria_service`      | Instructs the Signer to connect to Choria and start a service, otherwise HTTPS must be used to sign requests, strongly recommend to use this method |
| `allow_bearer_tokens` | This is needed to allow older Choria clients to connect, those did not sign their signing requests                                                  |

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

The broker will verify connections are signed by the Signer, all unsigned or non mTLS connections will be rejected.

Copy the `/etc/aaasvc/jwt-signer.pem` to the broker and set this configuration.

```ini
plugin.choria.network.client_signer_cert = /etc/choria/jwt-signer.pem
```

## Choria Client Configuration

Clients must know to login and requests signing be done, the `client.conf` settings enable that:

### Choria Network Based Signatures

```ini
plugin.choria.security.request_signer.token_file = ~/.choria/token
plugin.choria.security.request_signer.service = true
plugin.login.aaasvc.login.url = https://caaa.example.net/choria/v1/login
```

### HTTPS Based Signatures

While we strongly suggest signing via the Choria network, HTTP can also be used.

```ini
plugin.choria.security.request_signer.token_file = ~/.choria/token
plugin.choria.security.request_signer.url = https://caaa.example.net/choria/v1/sign
plugin.login.aaasvc.login.url = https://caaa.ams.devco.net/choria/v1/login
```


## Choria Server Configuration

There is no specific configuration required on Choria servers when using this method

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
    "signing_certificate": "/etc/aaasvc/jwt-signer.pem",
    "max_validity":"2h",
    "choria_service": true,
    "allow_bearer_tokens": true
  },
  "logfile_auditor": {
    "logfile": "/var/log/signer_audit.json"
  },
  "userlist_authenticator": {
    "validity": "1h",
    "signing_key": "/etc/aaasvc/signer-private.key",
    "users_file": "/etc/aaasvc/users.json"
  }
}
```
