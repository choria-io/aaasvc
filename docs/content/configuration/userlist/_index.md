+++
title = "Userlist Authenticator"
toc = true
weight = 30
pre = "<b>2.3. </b>"
+++

Authentication is the act of validating a person is who he claims to be, this is done using a username, token, 2FA or other similar means.

While authentication is provided by this tool, it's optional you might choose to create JWT tokens using another method of your choosing, the login feature will only be enabled if any authenticator is configured.

There is only one authenticator at the moment more might be added again in the future, for now you would set the `authenticator` key to `userlist` if you wish to enable it in a specific location.

Users are configured either statically in this configuration file or via an external file, the benefit of the external file is that it can be updated without restarting the service.

Passwords in the files are `bcrypt` encoded, we provide a utility:

```nohighlight
$ aaasvc crypt
test
$2a$05$tVM7WO82I.bpdNY6oXxEW.mo388JedJKEdIUqRb06HQ0/wWExyZ1O
```

Basic configuration for the Authenticator can be seen below:

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

| Property      | Description                                                                            |
|---------------|----------------------------------------------------------------------------------------|
| `users`       | Static list of users, see below                                                        |
| `users_file`  | Dynamically loaded list of users, see below                                            |
| `validity`    | JWT tokens issued by this service will be valid for this long, 1 hour is a good choice |
| `signing_key` | A RSA key used for signing tokens                                                      |

The additional new properties above related to TLS will be the TLS Configuration for the Web Service and the port sets
the port that service listens on.

### External File

We can create an external file with the following content, set the path to this file using `users_file`.  The benefit of this approach is that the file is read on every authentication request hence any chances to it will be immediately live without restarts:

```json
[
  {
    "username": "puppetadmin",
    "password": "$2y$05$c4b/0WZ5WJ3nhSZPN9m8keCUPlCYtNOTkqU4fDNEPCUy1C9Pfqn2e",
    "acls": [
      "puppet.*"
    ],
     "broker_permissions": {
        "events_viewer": true
     }
  }
]
```

Simply list all your users in this file.

### Static Configuration

Alternatively the users list above can simply be placed in-line in the configuration json file in the `users` key. Configuration will not be reloaded once started.

### User Permissions

Regardless of the method you pick we have a number of permissions you can set in `broker_permissions`. The list here is correct for `0.27.0`. For an up-to-date list see the [Go Documentation for your version of Choria](https://pkg.go.dev/github.com/choria-io/go-choria@v0.26.2/tokens#ClientPermissions)

| Permission                 | Description                                                                                               |
|----------------------------|-----------------------------------------------------------------------------------------------------------|
| `streams_admin`            | Enables full access to Choria Streams for all APIs                                                        |
| `streams_user`             | Enables user level access to Choria Streams, no stream admin features                                     |
| `events_viewer`            | Allows viewing lifecycle and auto agent events using API or `choria tool event` or `choria machine watch` |
| `election_user`            | Allows using leader elections                                                                             |
| `system_user`              | Allows accessing the Choria Broker system account without verified TLS                                    |
| `governor`                 | Enables access to Governors, cannot make new ones, also requires `streams_user` permission                |
| `org_admin`                | Has access to all subjects and broker system account                                                      |
| `fleet_management`         | Enables access to the choria server fleet for RPCs                                                        |
| `signed_fleet_management`  | Requires a user to have a valid signature by an AAA Service to interact with the fleet                    |
| `service`                  | Allows a token to have a longer than common lifetime, suitable for services users                         |
| `authentication_delegator` | has the right to sign requests on behalf of others                                                        |

Many of these properties only make sense in the Organization Issuer based deployment scenario.

### User Fleet Access Policies

In Choria you access fleet nodes via the name of the *Agent* and an *Action* on the specified Agent, further you can supply *Inputs* as arguments to the *Action*.

Access policies restricts which agents and actions can be accessed. For full details see later in the *Authorizer* section.

#### Action List

When the Authorization is configured using the `accesslist` Authorizer you set the `acls` property of the user. An example is `["puppet.status", "puppet.enable"]` to give access to 2 actions. See below for more details.

#### Open Policy Agent

When the Authorization is configured using the `opa` Authorizer you can either load the policy from a file or set it inline. For full examples see the Authorizers section,

The per-user policy can be set in the `opa_policy` as embedded string or in `opa_policy_file` which will be read from disk and embedded in the resulting JWT.
