## Centralised AAA for the Choria Orchestrator

Choria is traditionally a loosely coupled system with very few central components.  In certain environments centralised AAA / RBAC is desired, this package delivers that.

Read the [introductory blog post for background and motiviation](https://choria.io/blog/post/2019/01/23/central_aaa/)

The main motivation is to avoid the problems caused by having to do certificate management for every user, instead you have a central login and central authority who does AAA for every request.  This is more appropriate to the typical Enterprise environment, typical users will be happy with the default behavior.

## Status

This is under active development, see the Issues list for current outstanding items.

## Features

 * Authentication
   * [Okta identity cloud](https://okta.com/)
   * Static configured users
   * Capable of running centrally separate from signers
 * Authorization
   * JWT token claims based allow list for access to agents and actions
 * Auditing
   * Log file based auditing
   * Messages published to NATS Stream
 * Signing
   * JWT token based signer
   * Does not require access to the login service
   * Stateless capable of running regionally in clusters behind load balancers with no shared storage needs
 * Prometheus stats
 * CLI for encrypting secrets using bcrypt
 * Only supports HTTPS with verification disabled as clients lack certificates in this model

## General Configuration

Review the below Features Reference section and pick the authentication, signer and auditing systems that suits your needs.

You can choose to run the login service and the signer service in different locations - you might have a central login service with access to Okta but regional DCs only signing requests and never needing access to Okta.

Additionally you need:

 * A privileged certificate signed by the CA your Choria network trusts, by default these should be have CNAMEs `something.privileged.mcollective`
 * A key and certificate used for signing the JWT tokens, does not need to be from any particular CA
 * A key, certificate and CA file used to serve HTTPS requests, signed by a CA in the same chain as the clients
 * Configuration for the signer and the Choria framework.

### Signer Configuration

The signer uses a JSON file for configuration and lets you compose the system as you need it, below is a basic example:

```json
{
  "choria_config": "/etc/choria/signer/choria.conf",
  "logfile": "/var/log/aaasvc.log",
  "loglevel": "warn",
  "authenticator": "userlist",
  "auditors": ["logfile"],
  "authorizer": "actionlist",
  "signer": "basicjwt",
  "port": 8080,
  "monitor_port": 8081,
  "site": "london",
  "tls_certificate": "/etc/choria/signer/tls/cert.pem",
  "tls_key": "/etc/choria/signer/tls/key.pem",
  "tls_ca":  "/etc/choria/signer/tls/ca.pem",
  "basicjwt_signer": {
    "signing_certificate": "/etc/choria/signer/signer/pub.pem"
  },
  "logfile_auditor": {
    "logfile": "/var/log/choria_signer/audit.log"
  },
  "userlist_authenticator": {
    "signing_key": "/etc/choria/signer/signing/key.pem",
    "validity": "1h",
    "users": [
      {
        "username": "puppetadmin",
        "password": "$2y$05$c4b/0WZ5WJ3nhSZPN9m8keCUPlCYtNOTkqU4fDNEPCUy1C9Pfqn2e",
        "acls": [
          "puppet.*",
        ]
      }
    ]
  }
}
```

|Key|Description|
|---|-----------|
|choria_config|Configuration for the Choria framework, example below|
|logfile|Logfile for the service running info|
|loglevel|Level to log at - debug, info, warn|
|authenticator|The name of the authenticator to use, see feature reference|
|auditors|List of auditors to use, see feature reference|
|authorizer|Authorizer to use, see feature reference|
|signer|Signer to use, see feature reference|
|port|HTTP port to listen on for request|
|monitor_port|Port to serve prometheus stats on|
|site|Site to expose in prometheus stats|
|tls_certificate|Certificate used on the listening port|
|tls_key|Key used on the listening port|
|tls_ca|CA used to validate clients|
|basicjwt_signer|Configuration for the Basic JWT signer|
|logfile_auditor|Configuration for the Logfile Auditor|
|natsstream_auditor|Configuration for the NATS Stream auditor|
|okta_authenticator|Configuration for the Okta authenticator|
|userlist_authenticator|Configuration for the User List authenticator|

The Choria configuration file just need to configure the security system with the location of the privileged certificate:

```ini
plugin.security.provider = file
plugin.security.file.certificate = /etc/choria/signer/choria/signer.privileged.mcollective_cert.pem
plugin.security.file.key = /etc/choria/signer/choria/signer.privileged.mcollective_key.pem
plugin.security.file.ca = /etc/choria/signer/choria/privileged_ca.pem
```

There are many certificates here, lets look at the ones listed in the samples above:

|File|Description|
|----|-----------|
|signer/choria/*.pem|Certificate, key and CA used to sign requests within your DC, issued by the CA in the DC|
|signer/signing/*.pem|Certificate and Key used to sign JWT tokens, no particular need for a specific CA to sign it|
|signer/tls/*.pem|Certificate, Key and CA Chain that will communicate with clients requesting tokens and logins, must be issued such that clients will be trusted by the CA chain|

### Testing Login

Once configured you can use curl to test your login works:

```
curl -s --request POST -d '{"username":"puppetadmin", "password":"secret"}' -H "Content-type: application/json" -k https://localhost:8080/choria/v1/login
```

You should get a token back that you can decode using [jwt.io](https://jwt.io), it will look as below:

```json
{
  "agents": [
    "rpcutil.ping",
    "*",
    "puppet.*"
  ],
  "callerid": "okta=rip@choria.io",
  "exp": 1547742762
}
```

### Choria client configuration

You can configure your system wide Choria CLI with lines like here, this will enable it for everyone:

```ini
# usual settings omitted
plugin.choria.security.request_signer.url = http://localhost:8080/choria/v1/sign
plugin.choria.security.request_signer.token_environment = CHORIA_TOKEN
plugin.choria.security.request_signer.force = 1
```

You'll need to set the token in your shell:

```
export CHORIA_TOKEN=$(curl -s --request POST -d '{"username":"puppetadmin", "password":"secret"}' -H "Content-type: application/json" http://localhost:8080/choria/v1/login)
```

At this point you can use `mco` cli as always, requests will be sent to the signer for signing, users will not need their own certificates or use `mco choria request_cert`

## Features Reference
### Authentication

Authentication is the act of validating a person is who he claims to be, this is done using a username, token, 2FA or other similar means.

This supports a number of authentication schemes each would issue a JWT token to the user that will then be authorised and signed by a Signer.

While authentication is provided by this tool, it's optional you might choose to create JWT tokens using another method of your choosing, the login feature will only be enabled if any authenticator is configured.

#### Static Configuration

If using a service for this isn't for you you can also configure users and groups statically.

Passwords are encrypted using `bcrypt`, you can use apache httpasswd to encrypt the passwords:

```
% echo secret |caaa crypt
$2y$05$c4b/0WZ5WJ3nhSZPN9m8keCUPlCYtNOTkqU4fDNEPCUy1C9Pfqn2e
```

```json
{
  "authenticator": "userlist",
  "userlist_authenticator": {
    "signing_key": "/etc/choria/signer/signing_key.pem",
    "validity": "1h",
    "users": [
      {
        "username": "puppetadmin",
        "password": "$2y$05$c4b/0WZ5WJ3nhSZPN9m8keCUPlCYtNOTkqU4fDNEPCUy1C9Pfqn2e",
        "acls": [
          "puppet.*",
        ]
      }
    ]
  }
}
```

#### Okta

[Okta](https://www.okta.com/) is an identity cloud providing users, authentication and group membership as a service.  They have a great free tier suitable for many small sites and so is a good first step towards moving your users to a managed service.

This tool can authenticate users against Okta and retrieve the groups they belong to, based on those groups access is granted to certain Choria agents and actions.

Once you signed up for Okta and set up a application for Choria you'll get endpoints, client id, client secret and api token, put this in the configuration here.

```json
{
  "authenticator": "okta",
  "okta_authenticator": {
    "client_id": "xxx",
    "client_secret": "xxx",
    "api_token": "xxx",
    "endpoint": "https://xxx.oktapreview.com",
    "validity": "1h",
    "signing_key": "/etc/choria/signer/signing_key.pem",
    "acls": {
      "Everyone": ["rpcutil.ping"],
      "ChoriaAdmins": ["*"],
      "ChoriaPuppetAdmins": ["puppet.*"]
    }
  }
}
```

Here we configure `acls` based on Okta groups - all users can `rpcutil ping`, there are Puppet admins with appropriate rights and fleet wide admins capable of managing anything.

## Authorization

Authorization is how you declare what an authenticated user can do, in this system the JWT tokens have an `agents` claim with the following:

```json
{
  "agents": [
    "rpcutil.ping",
    "puppet.*"
  ]
}
```

The authorizers will then inspect this and determine if the user should be allowed to make a request he is requesting we sign.

### Action List

This the only support authorizer at present, it reads the `agents` claim in the JWT token and allow/deny the user.  Examples below.

 * `*` - all actions are allowed
 * `puppet.status` - one specific action is allowed
 * `puppet.*` - all actions in the puppet agent are allowed

Multiple agent entries can be listed in the claim and any that match will allow the request otherwise it gets denied.

```json
{
    "authorizer": "actionlist"
}
```

It has no specific configuration.

## Signing

The Signing service signs requests on behalf of CLI users, ths signing service has certificates that the Choria network trusts (known as privileged certificates).  The signer validates the JWT token is valid before signing.

Signers do not communicate directly with the Authentication service so you can run a central authenticator and signers in every location.

### BasicJWT

The only supported signer today is one that receives JWT tokens as issued by Okta or Userlist authentications, it inspects the request and should the token allow the request it will sign it and audit it.

```json
{
  "signer": "basicjwt",
  "basicjwt_signer": {
    "signing_certificate": "/etc/choria/signer/signing_cert.pem"
  }
}
```

The `signing_certificate` here is the public part of the signing key used by the Authenticators.  This is used to validate that the JWT was indeed issued by a trusted Authenticator.

## Auditing

Every signing action gets audited via an auditor, multiple auditors can be active at the same time and will be called in series.

### Logfile

This is a simple auditor that just writes a logfile of the actions taken.

```json
{
    "auditors": ["logfile"],
    "logfile_auditor": {
      "logfile": "/var/log/signer_audit.json"
    }
}
```

You have to arrange for rotation of this log file, each line will be a JSON line.

### NATS Stream

If you want to aggregate audit logs from your regional signers back to the central authentication service this is the auditor to use.

It publish structured messages to a NATS Stream topic that you can use the [Choria Stream Replicator](https://github.com/choria-io/stream-replicator) to transport these from your regional DC to central for consumption.

Published messages will match the [io.choria.signer.v1.signature_audit](https://choria.io/schemas/choria/signer/v1/signature_audit.json) JSON Schema.

```json
{
  "auditors": ["natsstream"],
  "natsstream_auditor": {
    "cluster_id": "test-cluster",
    "servers": "nats://localhost:4222",
    "topic": "audit"
  }
}
```

## Statistics

When `monitor_port` is set Prometheus statistics are reports on `/metrics`

|Statistic|Description|
|---------|-----------|
|choria_aaa_authenticator_errors|Total number of authentication requests that failed|
|choria_aaa_authenticator_time|Total time taken to perform authentication|
|choria_aaa_authorizer_allowed|Total number of requests that were allowed by the authorizer|
|choria_aaa_authorizer_denied|Total number of requests that were denied authorizer|
|choria_aaa_authorizer_errors|Total number of requests that could not be authorized|
|choria_aaa_auditor_errors|Total number of audit requests that failed|
|choria_aaa_auditor_natsstream_reconnects|Total number of times the NATS Streaming auditor reconnected to the middleware|
|choria_aaa_signer_errors|Total number of requests that could not be signed|
|choria_aaa_signer_allowed|Total number of requests that were allowed by the signer|
|choria_aaa_signer_denied|Total number of requests that were denied by the signer|
|choria_aaa_signer_invalid_token|Total number of signing requests that had invalid JWT tokens|