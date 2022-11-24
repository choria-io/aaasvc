+++
title = "Configuration"
toc = true
weight = 20
pre = "<b>2. </b>"
+++

Configuring the AAA Service requires exact knowledge of your deployment scenarios, we support 2 major approaches:

 * Deployment for users with Certificate Authorities and `puppet`, `file`, `certmanager` or `pkcs11` Choria Security System (the default)
 * Deployment for users with ED25519 based Organization Issuers and the `choria` Choria Security System

Most users, today, will fall in the first category.

## General Requirements

### Authenticator

You have to decide on an Authentication system to use. Internally we support just the `userlist` authenticator that takes a configuration
file of users and (encrypted) passwords along with their permissions. 

You can freely implement your own Authenticator using your own choice of technologies, you will then be responsible for issuing and 
signing correct Choria format JWT files.

### Authorizer

Each user will need a set of Permissions, and those who get Choria Fleet access via Choria RPC will need a policy attached.

 * `actionlist` - a simple list of Agent and Action pairs to which a user has access at all times
 * `opa` - an [Open Policy Agent](https://www.openpolicyagent.org/) based policy language that allows for greater control and expressiveness

It's worth starting with `actionlist` while learning the system.

### Auditor

As users make Choria requests we can produce a details audit trail of their requests and if those were allowed or not.

We support auditing to Choria Streams and to files, you can run multiple auditors at the same time.

### Signer

Realistically we have only one request signer that supports Choria JWT tokens. Review the configuration section specific
to this component for different scenarios.

### Monitoring

We expose metrics to Prometheus, for in-depth monitoring you will need Prometheus or a compatible system.
