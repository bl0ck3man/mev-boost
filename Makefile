VERSION ?= $(shell git describe --tags --always --dirty="-dev")
DOCKER_REPO := flashbots/mev-boost
MERGEMOCK_DIR=../mergemock
MERGEMOCK_BIN=./mergemock

.PHONY: all
all: build

.PHONY: v
v:
	@echo "${VERSION}"

.PHONY: build
build:
	go build -ldflags "-X 'github.com/flashbots/mev-boost/config.Version=${VERSION}' -X 'github.com/flashbots/mev-boost/config.BuildTime=$(shell date)'" -v -o mev-boost .

.PHONY: build-testcli
build-testcli:
	go build -ldflags "-X 'github.com/flashbots/mev-boost/config.Version=${VERSION}' -X 'github.com/flashbots/mev-boost/config.BuildTime=$(shell date)'" -v -o test-cli ./cmd/test-cli

.PHONY: test
test:
	go test ./...

.PHONY: test-race
test-race:
	go test -race ./...

.PHONY: lint
lint:
	revive -set_exit_status ./...
	go vet ./...
	staticcheck ./...

.PHONY: test-coverage
test-coverage:
	go test -race -v -covermode=atomic -coverprofile=coverage.out ./...
	go tool cover -func coverage.out

.PHONY: cover
cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func coverage.out
	unlink coverage.out

.PHONY: cover-html
cover-html:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out
	unlink coverage.out

.PHONY: run-mergemock-integration
run-mergemock-integration: build
	./scripts/run_mergemock_integration.sh

.PHONY: build-for-docker
build-for-docker:
	GOOS=linux go build -ldflags "-X 'github.com/flashbots/mev-boost/config.Version=${VERSION}' -X 'github.com/flashbots/mev-boost/config.BuildTime=$(shell date)'" -v -o mev-boost .

.PHONY: docker-image
docker-image:
	DOCKER_BUILDKIT=1 docker build . -t mev-boost
	docker tag mev-boost:latest ${DOCKER_REPO}:${VERSION}
	docker tag mev-boost:latest ${DOCKER_REPO}:latest

.PHONY: docker-push
docker-push:
	docker push ${DOCKER_REPO}:${VERSION}
	docker push ${DOCKER_REPO}:latest

.PHONY: clean
clean:
	git clean -fdx

run-boost-with-relay:
	./mev-boost -mainnet -relays http://0x821961b64d99b997c934c22b4fd6109790acf00f7969322c4e9dbf1ca278c333148284c01c5ef551a1536ddd14b178b9@127.0.0.1:28545 -collector http://localhost:8081/payload -sentry http://sentryDSN
