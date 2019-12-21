#!/bin/bash

set -x

yum -y install docker-client

cd "{{cpkg_name}}-{{cpkg_version}}"

cp dist/Dockerfile .

docker build . --tag "{{cpkg_user}}/{{cpkg_name}}:{{cpkg_version}}" --tag "{{cpkg_user}}/{{cpkg_name}}:latest"

mkdir /containers

docker save "{{cpkg_user}}/{{cpkg_name}}:{{cpkg_version}}" > "/containers/{{cpkg_name}}-{{cpkg_version}}.tar"