#!/bin/bash

CONF_FILE=/etc/gitlab-runner/config.toml

echo -e "Starting registration script...\n"
if [ ! -s "${CONF_FILE}" ]; then
    gitlab-runner register \
        --non-interactive \
        --url "http://gitlab" \
        --registration-token "${REGISTRATION_TOKEN}" \
        --executor "docker" \
        --docker-image "docker:23.0.1" \
        --docker-network-mode gitlab_net \
        --docker-volumes /var/run/docker.sock:/var/run/docker.sock \
        --description "docker-runner"
else
    echo -e "Ignoring registration : config.toml file not empty (already registered)."
fi
echo -e "End registration script. \n"
