|Date      |Issue |Description                                                                                              |
|----------|------|---------------------------------------------------------------------------------------------------------|
|2021/12/06|      |Release 0.6.0                                                                                            |
|2021/11/19|99    |Remove Okta and NATS Streaming Server support                                                            |
|2021/11/19|99    |Support signed requests using ed25519 public keys                                                        |
|2021/11/15|97    |Support client permissions                                                                               |
|2021/11/05|95    |Support new Choria client tokens                                                                         |
|2021/08/28|89    |Support signing requests via a Choria Service                                                            |
|2021/07/20|      |Release 0.5.0                                                                                            |
|2021/07/20|      |Move to `github.com/golang-jwt/jwt`                                                                      |
|2021/04/16|      |Various build tooling updates to support Podman and use go 1.16 everywhere                               |
|2021/04/13|81    |Support disabling mTLS by not setting a CA                                                               |
|2021/03/30|      |Release 0.4.0                                                                                            |
|2021/03/30|77    |Add a `ou` claim in the userlist authenticator for future multi tenancy support                          |
|2021/03/30|      |Upgrade to go 1.16, deprecate EL6 packages                                                               |
|2021/03/30|75    |Package for el8                                                                                          |
|2020/10/13|72    |Bounds check the agent claim                                                                             |
|2020/06/16|      |Release 0.3.3                                                                                            |
|2020/06/16|      |Update dependencies for `certmanager` support                                                            |
|2020/01/06|      |Release 0.3.2                                                                                            |
|2020/01/01|68    |Use common component for managing Rego evaluation                                                        |
|2019/12/29|66    |Support tracing Rego evaluation when in debug mode                                                       |
|2019/12/22|      |Release 0.3.1                                                                                            |
|2019/12/22|61    |Do not cache opa policies read from file                                                                 |
|2019/12/22|      |Release 0.3.0                                                                                            |
|2019/12/22|55    |Allow TLS to be disabled using `--disable-tls` for use in Kubernetes                                     |
|2019/12/21|2     |Allow users to be set in a separate file that gets hot reloaded                                          |
|2019/12/21|50    |Support NATS JetStream for auditing                                                                      |
|2019/12/21|48    |Support user properties                                                                                  |
|2019/12/19|42    |Support Open Policy Agent                                                                                |
|2019/04/19|      |Release 0.2.0                                                                                            |
|2019/04/19|34    |Run as the root user on el7 as well                                                                      |
|2019/02/15|      |Release 0.1.0                                                                                            |
|2019/02/14|30    |Include a UTC Unix time stamp in the nats notification                                                   |
|2019/02/14|28    |Instead of 0, 1 or 2 use unknown, allow or deny for the action taken in nats notifications               |
|2019/02/14|28    |Include the `site` that produced the audit message in the nats notification                              |
|2019/02/14|      |Release 0.0.3                                                                                            |
|2019/02/14|25    |Allow disabling authenticators and signers                                                               |
|2019/02/01|22    |Make callerids more compatible with mco standards                                                        |
|2019/02/01|21    |Enforce exp headers and do not accept ones that are too far in the future                                |
|2019/01/31|      |Release 0.0.2                                                                                            |
|2019/01/31|18    |Write token with mode `0600`                                                                             |
|2019/01/30|16    |Syntax fixes to login.rb                                                                                 |
|2019/01/30|12    |Correctly expose the agent and action being authorized to prometheus                                     |
|2019/01/30|11    |Place correct integer format date in the `iat` field of JWT tokens                                       |
|2019/01/30|10    |Expand the token path to allow `~` to be used in system wide configs                                     |
|2019/01/30|      |Release 0.0.1                                                                                            |
