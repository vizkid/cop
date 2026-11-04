.PHONY: build check install app check-app

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
PREFIX ?= $(HOME)/.local
LDFLAGS := -X main.version=$(VERSION)
APP := bin/cop.app
BUNDLE_ID ?= io.github.vizkid.cop
# v0.1.4-2-gabc1234 becomes 0.1.4; a bundle version takes digits and dots only.
SHORT_VERSION := $(patsubst v%,%,$(firstword $(subst -, ,$(VERSION))))

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

# copd in a bundle gets the bundle's name and icon wherever macOS or
# 1Password shows the process. Its SDK worker runs from the same path.
app: build
	@test "$$(uname)" = Darwin || { echo 'make app needs macOS'; exit 1; }
	rm -rf $(APP) bin/cop.iconset
	mkdir -p $(APP)/Contents/MacOS $(APP)/Contents/Resources bin/cop.iconset
	cp bin/copd $(APP)/Contents/MacOS/copd
	sed -e 's/@BUNDLE_ID@/$(BUNDLE_ID)/' -e 's/@SHORT_VERSION@/$(SHORT_VERSION)/' macos/Info.plist.in > $(APP)/Contents/Info.plist
	for size in 16 32 128 256 512; do \
		sips -z $$size $$size docs/cop.png --out bin/cop.iconset/icon_$${size}x$${size}.png >/dev/null; \
	done
	for size in 16 32 128 256; do \
		sips -z $$((size * 2)) $$((size * 2)) docs/cop.png --out bin/cop.iconset/icon_$${size}x$${size}@2x.png >/dev/null; \
	done
	iconutil -c icns bin/cop.iconset -o $(APP)/Contents/Resources/cop.icns
	rm -rf bin/cop.iconset
	codesign --force --sign - $(APP)

# Checks the macOS bundle that gives copd a name and icon in 1Password prompts.
check-app: app
	plutil -lint $(APP)/Contents/Info.plist
	test "$$(plutil -extract CFBundleExecutable raw $(APP)/Contents/Info.plist)" = copd
	test "$$(plutil -extract CFBundleIdentifier raw $(APP)/Contents/Info.plist)" = "$(BUNDLE_ID)"
	test "$$(plutil -extract CFBundleName raw $(APP)/Contents/Info.plist)" = cop
	test "$$(plutil -extract LSBackgroundOnly raw $(APP)/Contents/Info.plist)" = true
	test -s $(APP)/Contents/Resources/cop.icns
	codesign --verify --strict --deep $(APP)
	$(APP)/Contents/MacOS/copd --help >/dev/null
