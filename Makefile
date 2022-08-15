NAME=go-shadowsocks$(RELVER)
BINDIR=bin
RELDIR=release
GOBUILD=CGO_ENABLED=0 go build -ldflags '-w -s -buildid='
VER?=0
# The -w and -s flags reduce binary sizes by excluding unnecessary symbols and debug info
# The -buildid= flag makes builds reproducible

all: linux-amd64 linux-arm64 linux-riscv64 linux-loong64 linux-mips64le openbsd-amd64

linux-amd64:
	GOARCH=amd64 GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-arm64:
	GOARCH=arm64 GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-riscv64:
	GOARCH=riscv64 GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-loong64:
	GOARCH=loong64 GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mips64le:
	GOARCH=mips64le GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

openbsd-amd64:
	GOARCH=amd64 GOOS=openbsd $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

releases: all
	chmod +x $(BINDIR)/$(NAME)-*
	for name in $$(ls $(BINDIR)); do bsdtar -zcf $(RELDIR)/$$name-$(VER).tar.gz $(BINDIR)/$$name; done

clean:
	rm $(BINDIR)/*
	rm $(RELDIR)/*
