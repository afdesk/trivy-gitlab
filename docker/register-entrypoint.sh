#!/bin/bash

CONF_FILE=/etc/gitlab-runner/config.toml

echo -e "Starting registration script...\n"
if [ ! -s "${CONF_FILE}" ]; then
    gitlab-runner register \
    --non-interactive \
    --url "http://gitlab" \
    --registration-token "${REGISTRATION_TOKEN}" \
    --executor "docker" \
    --docker-image alpine:latest \
    --docker-network-mode "gitlab_net" \
    --description "docker-runner" \
    --tag-list "docker" \
    --run-untagged="true" \
    --locked="false" \
    --access-level="not_protected"
else
    echo -e "Ignoring registration : config.toml file not empty (already registered)."
fi
echo -e "End registration script. \n"