#!/bin/bash

set -x

cd "{{cpkg_name}}-{{cpkg_version}}"

docker build -f dist/Dockerfile --tag "{{cpkg_user}}/{{cpkg_name}}:{{cpkg_version}}" --tag "{{cpkg_user}}/{{cpkg_name}}:latest" .

mkdir /containers

docker save "{{cpkg_user}}/{{cpkg_name}}:{{cpkg_version}}" > "/containers/{{cpkg_name}}-{{cpkg_version}}-docker.tar"