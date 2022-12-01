+++
title = "OPA Authorizer"
toc = true
weight = 40
pre = "<b>2.4. </b>"
+++

The [Open Policy Agent](https://www.openpolicyagent.org/) based policies allow for very flexible policy to be embedded into the JWT tokens, it allows for policies we have never supported in the past:

* Ensuring filters are used to avoid huge blast radius requests by accident
* Ensuring specific fact, class or identity filters are used
* Ensuring a specific collective is used
* Contents of the JWT claim
* Checks based on the site the `aaasvc` is deployed in
* Checks on every input being sent to the action

This section covers the `opa` authorizer in detail and will include more detailed examples in time.

## Example

Here's a complex policy:

```rego
# must be in this package
package io.choria.aaasvc

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

## Functions

* `requires_filter()` - ensures that at least one of identity, class, compound of fact filters is not empty
* `requires_fact_filter("country=mt")` - ensures the specific fact filter is present in the request
* `requires_class_filter("apache")` - ensures the specific class filter is present in the request
* `requires_identity_filter("some.node")` - ensures the specific identity filter is present in the request

## Request Properties

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

## Configuration

In order to use this you have to set your Signer to use the `opa` Authorizer and have the `opa_policy` claim populated in user JWTs

```json
{
  "logfile": "/var/log/aaasvc.log",
  "loglevel": "warn",
  "site": "london",
  "authorizer": "opa"
}
```
