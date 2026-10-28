.PHONY: build check install

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
PREFIX ?= $(HOME)/.local
LDFLAGS := -X main.version=$(VERSION)

build:
	go build -ldflags "$(LDFLAGS)" -o bin/cop ./cmd/cop
	go build -ldflags "$(LDFLAGS)" -o bin/copd ./cmd/copd

# cop starts copd from its own directory, so both binaries install together.
install: build
	install -d "$(DESTDIR)$(PREFIX)/bin"
	install -m 0755 bin/cop bin/copd "$(DESTDIR)$(PREFIX)/bin/"

check:
	@test -z "$$(gofmt -l cmd internal experiments/desktop-sdk)" || { echo 'Run gofmt on Go source files'; exit 1; }
	go vet ./...
	go test -race -count=1 -timeout 2m ./...
	cd experiments/desktop-sdk && go vet ./... && go test -race -count=1 -timeout 2m ./...
