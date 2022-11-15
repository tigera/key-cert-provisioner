# Copyright (c) 2021 Tigera, Inc. All rights reserved.

PACKAGE_NAME    ?= github.com/tigera/key-cert-provisioner
GO_BUILD_VER    ?= v0.76
GIT_USE_SSH      = true

ORGANIZATION=tigera
SEMAPHORE_PROJECT_ID?=$(SEMAPHORE_KEY_CERT_PROVISIONER_PROJECT_ID)

ARCHES=amd64

RELEASE_BRANCH_PREFIX ?= release
DEV_TAG_SUFFIX        ?= 0.dev

DEV_REGISTRIES        ?= quay.io
RELEASE_REGISTRIES    ?= quay.io
BUILD_IMAGES          ?= tigera/key-cert-provisioner

PUSH_IMAGES           ?= $(foreach registry,$(DEV_REGISTRIES),$(addprefix $(registry)/,$(BUILD_IMAGES)))
RELEASE_IMAGES        ?= $(foreach registry,$(RELEASE_REGISTRIES),$(addprefix $(registry)/,$(BUILD_IMAGES)))

BINDIR?= bin

GO_FILES= $(shell sh -c "find pkg cmd -name \\*.go")
EXTRA_DOCKER_ARGS += -e GOPRIVATE=github.com/tigera/*

BUILD_DATE?=$(shell date -u +'%FT%T%z')
GIT_TAG?=$(shell git describe --tags)

VERSION_FLAGS=-X $(PACKAGE_NAME)/pkg/handler.VERSION=$(GIT_VERSION) \
	-X $(PACKAGE_NAME)/pkg/handler.BUILD_DATE=$(ES_PROXY_BUILD_DATE) \
	-X $(PACKAGE_NAME)/pkg/handler.GIT_COMMIT=$(GIT_COMMIT) \
	-X $(PACKAGE_NAME)/pkg/handler.GIT_TAG=$(GIT_TAG) \
	-X main.VERSION=$(GIT_VERSION)
BUILD_LDFLAGS=-ldflags "$(VERSION_FLAGS)"
RELEASE_LDFLAGS=-ldflags "$(VERSION_FLAGS) -s -w"

##############################################################################
# Download and include Makefile.common before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################
MAKE_BRANCH?=$(GO_BUILD_VER)
MAKE_REPO?=https://raw.githubusercontent.com/projectcalico/go-build/$(MAKE_BRANCH)

Makefile.common: Makefile.common.$(MAKE_BRANCH)
	cp "$<" "$@"
Makefile.common.$(MAKE_BRANCH):
	# Clean up any files downloaded from other branches so they don't accumulate.
	rm -f Makefile.common.*
	curl --fail $(MAKE_REPO)/Makefile.common -o "$@"

include Makefile.common

# We need CGO to leverage Boring SSL.  However, the cross-compile doesn't support CGO yet.
ifeq ($(ARCH), $(filter $(ARCH),amd64))
CGO_ENABLED=1
else
CGO_ENABLED=0
endif

$(BINDIR)/key-cert-provisioner-$(ARCH): $(GO_FILES)
ifndef RELEASE_BUILD
	$(eval LDFLAGS:=$(RELEASE_LDFLAGS))
else
	$(eval LDFLAGS:=$(BUILD_LDFLAGS))
endif
	$(DOCKER_RUN) -e CGO_ENABLED=$(CGO_ENABLED) $(CALICO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) \
			go build -o $@ $(LD_FLAGS) $(PACKAGE_NAME)/cmd'

build: $(BINDIR)/key-cert-provisioner-$(ARCH)

ut: build
	$(DOCKER_GO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) \
			go test ./...'

ci: clean static-checks ut

clean:
	rm -rf .go-pkg-cache \
		   bin \
		   Makefile.common*

image: tigera/key-cert-provisioner
tigera/key-cert-provisioner: tigera/key-cert-provisioner-$(ARCH)
tigera/key-cert-provisioner-$(ARCH): build
	docker buildx build --pull -t tigera/key-cert-provisioner:latest-$(ARCH) --file ./Dockerfile.$(ARCH) .
ifeq ($(ARCH),amd64)
	docker tag tigera/key-cert-provisioner:latest-$(ARCH) tigera/key-cert-provisioner:latest
endif

cd: image cd-common
