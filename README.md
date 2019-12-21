## Centralized AAA for the Choria Orchestrator

Choria is traditionally a loosely coupled system with very few central components.  In certain environments centralised AAA / RBAC is desired, this package delivers that.

Read the [introductory blog post for background and motivation](https://choria.io/blog/post/2019/01/23/central_aaa/)

The main motivation is to avoid the problems caused by having to do certificate management for every user, instead you have a central login and central authority who does AAA for every request.  This is more appropriate to the typical Enterprise environment, typical users will be happy with the default behavior.

With this deployed the workflow becomes:

```
$ mco ping
The ping application failed to run, use -v for full error backtrace details: could not find token in environment variable CHORIA_TOKEN

$ mco login
Username (rip):
Password:
Starting a new shell with CHORIA_TOKEN set, please exit when done

$ mco ping
---- ping statistics ----
19 replies max: 161.60 min: 131.23 avg: 151.21
```

The token is valid for a configurable period after which time another `mco login` will be required. Users are able to perform only the actions that they are entitled. Users have no SSL certificates of their own - a system wide certificate might be needed to connect to middleware if configured to require TLS.

## Status

This is under active development, see the Issues list for current outstanding items. Documentation and deployment details are sparse while it's being worked on, though its functional and we are happy to help you on our slack channel.

[![DeepSource](https://static.deepsource.io/deepsource-badge-light.svg)](https://deepsource.io/gh/choria-io/aaasvc/?ref=repository-badge)

## Features

 * Authentication
   * [Okta identity cloud](https://okta.com/)
   * Static configured users with support for basic agent+action ACLs as well as Open Policy Agent policies
   * Capable of running centrally separate from signers
 * Authorization
   * JWT token claims based allow list for access to agents and actions
   * JWT token claims based Open Policy Agent rego files
 * Auditing
   * Log file based auditing
   * Messages published to NATS Stream
 * Signing
   * JWT token based signer
   * Does not require access to the login service
   * Stateless capable of running regionally in clusters behind load balancers with no shared storage needs
 * Convenient `mco login` tool for authenticating to the service
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

There is a Puppet module [exaldraen-choria_aaasvc](https://forge.puppet.com/exaldraen/choria_aaasvc) which will automate the installation and configuration of the AAA service, but currently still requires you to provision the certificates manually.

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
    "signing_certificate": "/etc/choria/signer/signer/pub.pem",
    "max_validity":"2h"
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
          "puppet.*"
        ],
        "properties": {
          "group": "admins"
        }
      },
      {
        "username": "admin",
        "password": ".....",
        "properties": {
          "group": "admins"
        },
        "opa_policy_file": "/etc/choria/signer/common.rego"
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
|signer/tls/*.pem|Certificate, Key and CA Chain that will communicate with clients requesting tokens and logins, clients will disable verify when connecting|

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
plugin.choria.security.request_signer.url = https://localhost:8080/choria/v1/sign
plugin.choria.security.request_signer.token_environment = CHORIA_TOKEN
```

You'll need to set the token in your shell:

```
export CHORIA_TOKEN=$(curl -s --request POST -d '{"username":"puppetadmin", "password":"secret"}' -H "Content-type: application/json" https://localhost:8080/choria/v1/login)
```

At this point you can use `mco` cli as always, requests will be sent to the signer for signing, users will not need their own certificates or use `mco choria request_cert`

## Features Reference
### Authentication

Authentication is the act of validating a person is who he claims to be, this is done using a username, token, 2FA or other similar means.

This supports a number of authentication schemes each would issue a JWT token to the user that will then be authorized and signed by a Signer.

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
      },
      {
        "username": "admin",
        "password": ".....",
        "opa_policy_file": "/etc/choria/signer/common.rego"
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

Authorization is how you declare what an authenticated user can do, in this system the JWT tokens can contain either a simple agent/action list or a full features [Open Policy Agent](https://www.openpolicyagent.org/) based policy.


Authorization is how you declare what an authenticated user can do, in this system the JWT tokens have an `agents` claim with the following:

The authorizers will then inspect this and determine if the user should be allowed to make a request he is requesting we sign.

### Action List

This authorizer reads the `agents` claim in the JWT token and allow/deny the user.  Examples below.

```json
{
  "agents": [
    "rpcutil.ping",
    "puppet.*"
  ]
}
```

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

### Open Policy Agent

The Open Policy Agent based policies allow for very flexible policy to be embedded into the JWT tokens, it allow for policies we have never supported in the past:

 * Ensuring filters are used to avoid huge blast radius requests by accident
 * Ensuring specific fact, class or identity filters are used
 * Ensuring a specific collective is used
 * Contents of the JWT claim
 * Checks based on the site the aaasvc is deployed in
 * Checks on every input being sent to the action

Here's a complex policy:

```rego
# must be in this package
package choria.aaa.policy

# it only checks `allow`, its good to default false
default allow = false

# user can deploy only frontend of myco into production but only in malta
allow {
	input.action == "deploy"
	input.agent == "myco"
	input.data.component == "frontend"
	requires_fact_filter("country=mt")
	input.collective == "production"
}

# can ask status anywhere in any environment
allow {
	input.action == "status"
	input.agent == "myco"
}

# user can do anything myco related in development
allow {
	input.agent == "myco"
	input.collective == "development"
}
```

Here we use the `requires_fact_filter()` to ensure a specific fact filter is used, we have these custom functions:

 * `requires_filter()` - ensures that at least one of identity, class, compound of fact filters is not empty
 * `requires_fact_filter("country=mt")` - ensures the specific fact filter is present in the request
 * `requires_class_filter("apache")` - ensures the specific class filter is present in the request
 * `requires_identity_filter("some.node")` - ensures the specific identity filter is present in the request

And you'll have these input items at your disposal:

 * `agent` - the agent being invoked
 * `action` - the action being invoked
 * `data` - the contents of the request - all the inputs being sent to the action
 * `sender` - the sender host
 * `collective` - the targeted sub collective
 * `ttl` - the ttl of the request
 * `time` - the time the request was made
 * `site` - the site hosting the aaasvcs (from its config)
 * `claims` - all the JWT claims

You can store this in a file and specify the user in the userlist plugin like this:

```json
  {
    "username": "admin",
    "password": ".....",
    "opa_policy_file": "/etc/choria/signer/admin.rego"
  }
```

To activate this authorizer configure it like this:

```json
{
    "authorizer": "opa"
}
```

## Signing

The Signing service signs requests on behalf of CLI users, ths signing service has certificates that the Choria network trusts (known as privileged certificates).  The signer validates the JWT token is valid before signing.

Signers do not communicate directly with the Authentication service so you can run a central authenticator and signers in every location.

### BasicJWT

The only supported signer today is one that receives JWT tokens as issued by Okta or Userlist authentications, it inspects the request and should the token allow the request it will sign it and audit it.

```json
{
  "signer": "basicjwt",
  "basicjwt_signer": {
    "signing_certificate": "/etc/choria/signer/signing_cert.pem",
    "max_validity": "24h"
  }
}
```

The `signing_certificate` here is the public part of the signing key used by the Authenticators.  This is used to validate that the JWT was indeed issued by a trusted Authenticator.

`max_validity` is the maximum amount of time from the present that the received JWT token is allowed in its `exp` field, this avoid infinite length tokens from being issued that can be a huge security risk.

Tokens without `exp` will be denied in all cases.

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

When `monitor_port` is set Prometheus statistics are reported on `/metrics`

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
