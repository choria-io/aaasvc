package choria.aaa.policy

default allow = false

allow {
    input.agent == "myco"
    input.action == "deploy"
}