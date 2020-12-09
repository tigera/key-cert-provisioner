.DEFAULT_GOAL := docker-image

IMAGE ?= quay.io/tigera/key-cert-provisioner:master

bin/init-container: $(shell find . -name '*.go')
	CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o $@ ./cmd

.PHONY: docker-image
docker-image: bin/init-container
	docker build -t $(IMAGE) ./

.PHONY: push-image
push-image: docker-image
	docker push $(IMAGE)

