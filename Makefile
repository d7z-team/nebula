GOLANGCI_LINT_PACKAGE ?= github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0

.PHONY: check fmt test race vet tidy

check: vet test

fmt:
	go run $(GOLANGCI_LINT_PACKAGE) fmt ./...

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

tidy:
	go mod tidy
