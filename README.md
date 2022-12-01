![Choria AAA Service](https://choria-io.github.io/aaasvc/logo.png)

## Overview

Choria is traditionally a loosely coupled system with very few central components.  When a user makes a RPC request the request has a public certificate attached and every single node they interact with does RBAC.

That default deployment method has no dependencies per request and scales very well but it can be difficult to manage, rotate and audit who has access credentials.  This package provides a system that issues short-lived JWT tokens and authorize and audit each request centrally prior to communicating with any fleet nodes.

The main motivation is to avoid the problems caused by having to do Certificate Management and Fleet wide static Action Policies for every user, instead you have a central login and central authority who does AAA for every request.  This is more appropriate to the typical Enterprise environment.

* [Documentation](https://choria-io.github.io/aaasvc/)
* [Community](https://github.com/choria-io/general/discussions)

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

[![Go Report Card](https://goreportcard.com/badge/github.com/choria-io/aaasvc)](https://goreportcard.com/report/github.com/choria-io/aaasvc)
[![CodeQL](https://github.com/choria-io/aaasvc/workflows/CodeQL/badge.svg)](https://github.com/choria-io/aaasvc/actions/workflows/codeql.yaml)
[![Unit Tests](https://github.com/choria-io/aaasvc/actions/workflows/test.yaml/badge.svg)](https://github.com/choria-io/aaasvc/actions/workflows/test.yaml)
