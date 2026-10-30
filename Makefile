.PHONY: all build-linux build-darwin clean

all: build-linux build-darwin

build-linux:
	@echo "Building standalone Linux amd64 binaries..."
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/inplace_restore_linux_amd64 src/inplace_restore.go
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/scan_master_linux_amd64 src/scan_master.go

build-darwin:
	@echo "Building standalone macOS arm64 binaries..."
	GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o bin/inplace_restore_darwin_arm64 src/inplace_restore.go
	GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o bin/scan_master_darwin_arm64 src/scan_master.go

clean:
	rm -rf bin/*
