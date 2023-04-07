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

<!-- #### Allow insecure registry
Add follow to docker daemon config
```json
{
    "insecure-registries" : ["registry:5000", "gitlab.local:5005"]
}
```
- for macos ~/.docker/daemon.json
- for linux etc/dcoker/daemon.json

Restart docker service -->


### Install runner

1. Go to http://localhost/admin/runners
2. Copy registration token
3. `export REGISTRATION_TOKEN=...`

Start register and runner
```shell
docker-compose -f docker/docker-compose.runner.yaml up -d
```
<!-- 
Connect to runner and add `network_mode = "gitlab_net"` to etc/gitlab-runner/config.toml in `[runners.docker]` section:
```yaml
concurrent = 1
check_interval = 0
shutdown_timeout = 0

[session_server]
  session_timeout = 1800

[[runners]]
  name = "616201193c6d"
  url = "http://gitlab"
  id = 1
  token = "kL5Em9Kjxtswu3x9MTBM"
  token_obtained_at = 2023-04-07T07:03:19Z
  token_expires_at = 0001-01-01T00:00:00Z
  executor = "docker"
  [runners.cache]
    MaxUploadedArchiveSize = 0
  [runners.docker]
    tls_verify = false
    image = "docker:23.0.1"
    privileged = true
    disable_entrypoint_overwrite = false
    oom_kill_disable = false
    disable_cache = false
    volumes = ["/cache"]
  + network_mode = "gitlab_net"
    shm_size = 0
``` -->

### Build plugin

```shell
make build-plugin
```

### Grant access to the directory via http

This will allow `trivy` to extract the archive with the plugin from the working directory.

Share directory
```shell
ngrok http "file://${PWD}"
```

Example:
```shell
trivy plugin run http://{ngrok_url}/trivy-gitlab.tar.gz container minio/minio:latest
```

## Quick start

<!-- During local testing, to resolve an unsafe register (because http), you need to add the following lines to all pipelines:
```yaml
variables:
  DOCKER_TLS_CERTDIR: ""

services:
  - name: docker:dind
    command: [ "--insecure-registry=gitlab.local:5005" ]
``` -->

1. Create repo
2. Create dockerfile
3. Configure pipline


TODO
https://github.com/hutchgrant/gitlab-docker-local/blob/master/README.md
https://github.com/danieleagle/gitlab-https-docker#generating-a-self-signed-certificate