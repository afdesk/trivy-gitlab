.PHONY: build
build:
	go build ./cmd/trivy-gitlab


.PHONY: install
install:
	go install ./cmd/trivy-gitlab