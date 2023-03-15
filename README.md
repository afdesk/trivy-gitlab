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
docker network create gitlab_net
```

### Install gitlab

Run gitlab
```shell
docker-compose -f docker/docker-compose.gitlab.yaml up -d
```

Visit http://gitlab.local/admin/runners, and sign in with the username `root` and the password from the following command:

```shell
docker exec -it gitlab grep 'Password:' /etc/gitlab/initial_root_password
```

### Install runner

Go to http://gitlab.local/admin/runners, create `REGISTRATION_TOKEN` and put it to `docker/.env`

Start register and runner
```shell
docker-compose -f docker/docker-compose.runner.yaml up -d
```

### ...

Share directory
```shell
ngrok http $PWD
```