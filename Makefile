prefix ?= /usr/local
exec_prefix ?= $(prefix)
bindir ?= $(exec_prefix)/bin

.PHONY: all install uninstall test update-vendor

all:
	go build -mod vendor -v .

install:
	GOBIN=$(bindir) go install -mod vendor -v .

uninstall:
	rm -f $(bindir)/gosignify

test:
	go test -mod vendor -v ./...

update-vendor:
	rm -rf vendor
	go get -u
	go mod vendor
