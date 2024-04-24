# Copyright (c) 2021 Tigera, Inc. All rights reserved.

PACKAGE_NAME    ?= github.com/tigera/key-cert-provisioner

GO_BUILD_VER    ?= v0.89
GIT_USE_SSH      = true

ORGANIZATION=tigera
SEMAPHORE_PROJECT_ID?=$(SEMAPHORE_KEY_CERT_PROVISIONER_PROJECT_ID)

ARCHES=amd64

RELEASE_BRANCH_PREFIX ?= release
DEV_TAG_SUFFIX        ?= 0.dev

DEV_REGISTRIES        ?= quay.io
RELEASE_REGISTRIES    ?= quay.io
BUILD_IMAGES          ?= tigera/key-cert-provisioner tigera/test-signer

PUSH_IMAGES           ?= $(foreach registry,$(DEV_REGISTRIES),$(addprefix $(registry)/,$(BUILD_IMAGES)))
RELEASE_IMAGES        ?= $(foreach registry,$(RELEASE_REGISTRIES),$(addprefix $(registry)/,$(BUILD_IMAGES)))

BINDIR?= bin

GO_FILES= $(shell sh -c "find pkg cmd -name \\*.go")
EXTRA_DOCKER_ARGS += -e GOPRIVATE=github.com/tigera/*

BUILD_DATE?=$(shell date -u +'%FT%T%z')
GIT_TAG?=$(shell git describe --tags)

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

GOFLAGS = -buildvcs=false
include Makefile.common

# Build a static binary with boring crypto support.
# This function expects you to pass in two arguments:
#   1st arg: path/to/input/package(s)
#   2nd arg: path/to/output/binary
# Only when arch = amd64 it will use boring crypto to build the binary.
# Uses LDFLAGS, CGO_LDFLAGS, CGO_CFLAGS when set.
# Tests that the resulting binary contains boringcrypto symbols.
define build_static_cgo_boring_binary
    $(DOCKER_RUN) \
        -e CGO_ENABLED=1 \
        -e CGO_LDFLAGS=$(CGO_LDFLAGS) \
        -e CGO_CFLAGS=$(CGO_CFLAGS) \
        $(GO_BUILD_IMAGE):$(GO_BUILD_VER) \
        sh -c '$(GIT_CONFIG_SSH) \
            GOEXPERIMENT=boringcrypto go build -o $(2)  \
            -tags fipsstrict,osusergo,netgo$(if $(BUILD_TAGS),$(comma)$(BUILD_TAGS)) -v \
            -ldflags "$(LDFLAGS) -linkmode external -extldflags -static -s -w" \
            $(1) \
            && strings $(2) | grep '_Cfunc__goboringcrypto_' 1> /dev/null'
endef

$(BINDIR)/key-cert-provisioner-$(ARCH): $(GO_FILES)
	$(call build_static_cgo_boring_binary, cmd/main.go, $@)

build: $(BINDIR)/key-cert-provisioner-$(ARCH) $(BINDIR)/test-signer-$(ARCH)

ut: build
	$(DOCKER_GO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) \
			go test ./...'

ci: clean static-checks ut

clean:
	rm -rf .go-pkg-cache \
		   bin \
		   Makefile.common*

###############################################################################
# BUILD IMAGE
###############################################################################
DOCKER_BUILD+=--pull

# Add --squash argument for CICD pipeline runs only to avoid setting "experimental",
# for Docker processes on personal machine.
# set `DOCKER_BUILD=--squash make image` to squash images locally.
ifdef CI
DOCKER_BUILD+= --squash
endif

image: tigera/key-cert-provisioner tigera/test-signer-image
tigera/key-cert-provisioner: tigera/key-cert-provisioner-$(ARCH)
tigera/key-cert-provisioner-$(ARCH): build
	docker build --pull -t tigera/key-cert-provisioner:latest-$(ARCH) --file ./Dockerfile.$(ARCH) .
ifeq ($(ARCH),amd64)
	docker tag tigera/key-cert-provisioner:latest-$(ARCH) tigera/key-cert-provisioner:latest
endif

cd: image cd-common

bin/test-signer-$(ARCH): $(GO_FILES)
	$(call build_static_cgo_boring_binary, test-signer/test-signer.go, $@)

tigera/test-signer-image: bin/test-signer-$(ARCH)
	docker buildx build --pull -t tigera/test-signer:latest-$(ARCH) --file ./test-signer/Dockerfile.$(ARCH) .
ifeq ($(ARCH),amd64)
	docker tag tigera/test-signer:latest-$(ARCH) tigera/test-signer:latest
endif
