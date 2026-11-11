.PHONY: check test race vet tidy

check: vet test

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

tidy:
	go mod tidy
