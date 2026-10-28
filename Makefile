.PHONY: build check

build:
	go build -o bin/cop ./cmd/cop
	go build -o bin/copd ./cmd/copd

check:
	@test -z "$$(gofmt -l cmd internal experiments/desktop-sdk)" || { echo 'Run gofmt on Go source files'; exit 1; }
	go vet ./...
	go test -race -count=1 -timeout 2m ./...
	cd experiments/desktop-sdk && go vet ./... && go test -race -count=1 -timeout 2m ./...
