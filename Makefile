prefix ?= /usr/local
exec_prefix ?= $(prefix)
bindir ?= $(exec_prefix)/bin

.PHONY: all install uninstall test update-vendor

all:
	env GO111MODULE=on go build -mod vendor -v .

install:
	env GO111MODULE=on GOBIN=$(bindir) go install -mod vendor -v .

uninstall:
	rm -f $(bindir)/gosignify

test:
	gocheck -g -c

update-vendor:
	rm -rf vendor
	env GO111MODULE=on go get -u
	env GO111MODULE=on go mod vendor
