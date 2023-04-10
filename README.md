# trivy-gitlab

## Configure the dev environment

### Set up the volumes location

For Linux users:
```shell
export GITLAB_HOME=/srv/gitlab
```

For MacOS users:
```shell
export GITLAB_HOME=$HOME/gitlab
```

### Create volumes and a network

```shell
docker volume create gitlab-data
docker volume create gitlab-runner-config
docker volume create registry-data
docker network create gitlab_net
```

### Install gitlab

Run gitlab
```shell
docker-compose -f docker/docker-compose.gitlab.yaml up -d
```

Visit http://localhost, and sign in with the username `root` and the password from the following command:

```shell
docker exec -it gitlab grep 'Password:' /etc/gitlab/initial_root_password
```


Don't forget to change your password!!

Make sure that the container registry is working:
```shell
docker login gitlab.local:5005
docker pull alpine
docker tag alpine gitlab.local:5005/{gitlab_instance_id}/monitoring
docker push gitlab.local:5005/{gitlab_instance_id}/monitoring
```

#### Allow insecure registry
Add follow to docker daemon config
```json
{
    "insecure-registries" : ["registry:5000", "gitlab.local:5005"]
}
```
- for macos ~/.docker/daemon.json
- for linux etc/dcoker/daemon.json

Restart docker service.


### Install runner

1. Go to http://localhost/admin/runners
2. Copy registration token
3. `export REGISTRATION_TOKEN=...`

Start register and runner
```shell
docker-compose -f docker/docker-compose.runner.yaml up -d

### Build plugin

```shell
make build-plugin
```

### Grant access to the directory via http

This will allow `trivy` to extract the archive with the plugin from the working directory.

Share directory
```shell
ngrok http "file://${PWD}"
export NGROK_URL=$(curl -s localhost:4040/api/tunnels | jq -r '.tunnels[0].public_url')
```

Put ngrok public url to plugin.yaml and templates

Example:
```shell
trivy plugin run http://{ngrok_url}/trivy-gitlab.tar.gz container minio/minio:latest
```

## Quick start

1. Create repo
2. Create dockerfile
3. Configure pipline


TODO
https://github.com/hutchgrant/gitlab-docker-local/blob/master/README.md
https://github.com/danieleagle/gitlab-https-docker#generating-a-self-signed-certificate