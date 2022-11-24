+++
weight = 5
+++

# Overview

Choria is traditionally a loosely coupled system with very few central components.  When a user makes a RPC request the request has a public certificate attached and every single node they interact with does RBAC. 

That default deployment method has no dependencies per request and scales very well but it can be difficult to manage, rotate and audit who has access credentials.  This package provides a system that issues short-lived JWT tokens and authorize and audit each request centrally prior to communicating with any fleet nodes. 

The main motivation is to avoid the problems caused by having to do Certificate Management and Fleet wide static Action Policies for every user, instead you have a central login and central authority who does AAA for every request.  This is more appropriate to the typical Enterprise environment.

With this deployed the workflow becomes:

```
$ choria ping
FATA[0000] Could not run Choria: could not perform request: error from remote signer: Request denied

$ mco login
Username (rip):
Password:
Token saved to /home/user/.choria/client.jwt

$ choria ping
...
---- ping statistics ----
19 replies max: 161.60 min: 131.23 avg: 151.21
```

The token is valid for a configurable period after which time another `choria login` will be required. Users are able to perform only the actions that they are entitled. Users have no SSL certificates of their own - a system-wide certificate might be needed to connect to middleware if configured to require TLS.

## Flow

Architecturally we designed this service so it can, optionally, be deployed in 2 parts. In your typical enterprise there might be a IAM service implementing something like SAML that is run centrally by a dedicated team and with restricted access to your SSO backend. Once the central IAM Service issued the JWT no further dependency exist on that resource for interacting with Choria.

![AAA Flow](aaa-flow.png)

 * A User (1) wish to use Choria to interact with the fleet or access Choria Streams.  They run `choria login` and authenticates to a service
 * The external authentication service (2) issues a Choria JWT with policies, permissions and more embedded in the JWT
 * If accessing Choria Streams or NATS messaging the user goes ahead and connects to the broker with their JWT token, broker will grant them appropriate permissions
 * If accessing the fleet of Choria Servers using RPC every request is signed by a Request Signing Service (3) that will evaluate Open Policy Agent policies per user 

This AAA Service includes:

 * User + Password based Authentication
 * Open Policy Agent based as well as, easier to use, allowed agent+action pair lists for Authorization
 * Auditing to file or Choria Streams

We support some hybrid deployments where only the Login service exist but fleet access is done without central signer dependency, more details about those in other areas of this documentation.

## Feature List

* Authentication
    * Static configured users with support for basic agent+action ACLs as well as Open Policy Agent policies
    * Capable of running centrally separate from signers
    * Enterprises can provide their own authentication backends, integration with technologies like SAML
    * JWT token permissions
    * Support for Choria Protocol 2.0 signature chains and Organization Issuers
* Authorization
    * JWT token claims based allow list for access to agents and actions
    * JWT token claims based Open Policy Agent rego files
* Auditing
    * Log file based auditing
    * Messages published to Choria Streams
* Signing
    * JWT token based signer
    * Does not require access to the login service
    * Stateless capable of running regionally in clusters behind load balancers with no shared storage needs
* Compatible with `choria login`
* Prometheus statistics
* CLI for encrypting secrets using bcrypt

## Status

This project and the Choria authentication landscape in general, is in a period of flux as we move to support a fully Certificate Authority free deployment strategy.

This project can be used today, even by users deploying with Puppet and has proven to be stable and scalable. In a future deployment scenario it will be central to the scalable operation of Choria.
