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

Add `127.0.0.1 gitlab.local` to hosts file

#### Allow insecure registry
Add follow to docker daemon config
```json
{
    "insecure-registries" : ["registry:5000", "gitlab.local:5005"]
}
```
- for macos ~/.docker/daemon.json
- for linux /etc/docker/daemon.json

Ref: https://docs.docker.com/config/daemon/

Restart docker service.


### Install runner

1. Go to http://localhost/admin/runners
2. Copy registration token
3. `export REGISTRATION_TOKEN=U11wSDywHkJz38hCJU1_`

Start register and runner
```shell
docker-compose -f docker/docker-compose.runner.yaml up -d
```

### Build plugin and run

```shell
make build-plugin

trivy plugin run $(PWD) container minio/minio:latest -- --debug=true --report-path=$(PWD)/data --template-path $(PWD)/templates/report/container-scanning.tpl
```

### Grant access to the directory via http

This will allow `trivy` to extract the archive with the plugin from the working directory.

Share directory
```shell
ngrok http "file://${PWD}"
export NGROK_URL=$(curl -s localhost:4040/api/tunnels | jq -r '.tunnels[0].public_url')
```

Put ngrok public url to plugin.yaml and templates

### Validation of the scan report

1. Run the go app locally
2. Execute: `./dev/validate {scanning_result_file}`


## Quick start (dev)

1. Put ngrok public url to `plugin.yaml` and in the files in  `templates/`
2. Edit `plugin.yaml`:

```yaml
platforms:
    - uri: ./trivy-gitlab
      bin: ./trivy-gitlab
```

3. Create a project/repo
4. Add a pipline, e.g:

```yaml
include:
    - remote: 'https://214f-92-124-160-226.ngrok-free.app/templates/jobs/container-scanning.gitlab-ci.yml'

stages:
    - build
    - test

variables:
    SOURCE_IMAGE: python
    CONTAINER_TEST_IMAGE: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA

build_img:
    stage: build
    script:
        - docker pull $SOURCE_IMAGE
        - docker tag $SOURCE_IMAGE $CONTAINER_TEST_IMAGE
        - docker login -u “$CI_REGISTRY_USER” -p “$CI_REGISTRY_PASSWORD” $CI_REGISTRY
        - docker push $CONTAINER_TEST_IMAGE
        - docker logout

trivy_container_scanning:
    stage: test
    variables:
        CS_IMAGE: $CONTAINER_TEST_IMAGE
```

--- 

TODO:
- https://github.com/hutchgrant/gitlab-docker-local/blob/master/README.md
- https://github.com/danieleagle/gitlab-https-docker#generating-a-self-signed-certificate