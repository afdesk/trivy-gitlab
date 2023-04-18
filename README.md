# trivy-gitlab

## Usage

### Container scanning

Example for docker socket binding

```yaml

include:
    - remote: 'https://raw.githubusercontent.com/afdesk/trivy-gitlab/main/templates/jobs/container-scanning.gitlab-ci.yml'

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
        TS_IMAGE: $CONTAINER_TEST_IMAGE

```

### Filesystem Scanning

```yaml
include:
    - remote: 'https://raw.githubusercontent.com/afdesk/trivy-gitlab/main/templates/jobs/fs-scanning.gitlab-ci.yml'

stages:
    - test

trivy-fs_scanning:
    variables:
        GIT_STRATEGY: clone


```

If you are using docker-in-docker, just add the following:

```yaml
image: docker:20.10

services:
    - docker:20.10-dind
```

Allowed variables for all jobs:
- TS_SCANNERS - list of scanners. 
  - By default `vuln` for [container](https://aquasecurity.github.io/trivy/v0.40/docs/target/container_image/). Available scanners: `vuln`
  - By default `vuln,config,secrets` for [filesystem](https://aquasecurity.github.io/trivy/v0.40/docs/target/filesystem/#scanners) scanner. Available scanners: `vuln,config,secrets`
- TS_CYCLONDEX - if false, cyclonedx report generation is disabled (enabled by default)

Specific variables for the container scanner:
- TS_IMAGE - name of the image to scan. If not specified, the image name is resolved according to the [following rules](https://docs.gitlab.com/ee/development/integrations/secure.html#container-scanning).

The scanner supports the [following variables](https://docs.gitlab.com/ee/development/integrations/secure.html#policies).

Note: 

If the number of commits is greater than the value of the variable GIT_DEPTH CI/CD, secret detection fails to detect the commit when the secret was added.