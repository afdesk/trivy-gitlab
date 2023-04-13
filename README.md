# trivy-gitlab

## Usage

### Container scanning

#### Docker-in-Docker

```yaml
image: docker:20.10

services:
    - docker:20.10-dind

include:
    - remote: 'https://raw.githubusercontent.com/afdesk/trivy-gitlab/main/templates/jobs/container-scanning.gitlab-ci.yml'

variables:
    CONTAINER_TEST_IMAGE: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
    DOCKER_TLS_CERTDIR: '/certs'

stages:
    - build
    - test

build_img:
    stage: build
    script:
        - docker build -t $CONTAINER_TEST_IMAGE
        - docker login -u “$CI_REGISTRY_USER” -p “$CI_REGISTRY_PASSWORD” $CI_REGISTRY
        - docker push $CONTAINER_TEST_IMAGE
        - docker logout

trivy-container-dind_scanning:
    stage: test
    variables:
        CS_IMAGE: python
```

#### Docker socket binding

```yaml

include:
    - remote: 'https://raw.githubusercontent.com/afdesk/main/trivy-gitlab/templates/jobs/container-scanning.gitlab-ci.yml'

variables:
    CONTAINER_TEST_IMAGE: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA

stages:
    - build
    - test

build_img:
    stage: build
    script:
        - docker build -t $CONTAINER_TEST_IMAGE
        - docker login -u “$CI_REGISTRY_USER” -p “$CI_REGISTRY_PASSWORD” $CI_REGISTRY
        - docker push $CONTAINER_TEST_IMAGE
        - docker logout

trivy-container-socket_scanning:
    stage: test
    variables:
        CS_IMAGE: $CONTAINER_TEST_IMAGE

```

### Filesystem Scanning

```yaml
include:
    - remote: 'https://raw.githubusercontent.com/afdesk/trivy-gitlab/main/templates/jobs/dependency-scanning.gitlab-ci.yml'
    - remote: 'https://raw.githubusercontent.com/afdesk/trivy-gitlab/main/templates/jobs/misconfig-detection.gitlab-ci.yml'
    - remote: 'https://raw.githubusercontent.com/afdesk/trivy-gitlab/main/templates/jobs/secret-detection.gitlab-ci.yml'

stages:
    - test


```