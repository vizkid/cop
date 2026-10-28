.PHONY: build check

build:
	go build -o bin/cop ./cmd/cop
	cd experiments/desktop-sdk && go build -o ../../bin/cop-sdk-worker ./worker

check:
	@test -z "$$(gofmt -l cmd internal experiments/desktop-sdk)" || { echo 'Run gofmt on Go source files'; exit 1; }
	go vet ./...
	go test -race -count=1 -timeout 2m ./...
	cd experiments/desktop-sdk && go vet ./... && go test -race -count=1 -timeout 2m ./...
