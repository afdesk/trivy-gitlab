# trivy-gitlab

## Usage

### Container scanning


Example for docker socket binding

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

trivy-container_scanning:
    stage: test
    variables:
        CS_IMAGE: $CONTAINER_TEST_IMAGE

```

### Filesystem Scanning

```yaml
include:
    - remote: 'https://raw.githubusercontent.com/afdesk/trivy-gitlab/main/templates/jobs/fs-scanning.gitlab-ci.yml'

stages:
    - test


```

If you use docker-in-docker just add follow:

```yaml
image: docker:20.10

services:
    - docker:20.10-dind
```

