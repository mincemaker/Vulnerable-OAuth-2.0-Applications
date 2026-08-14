-include .env
IMAGE_NAME ?= gallery-idp:latest

.PHONY: build build-frontend dev test clean install docker-build

build: build-frontend
	go build -o gallery-idp ./cmd/gallery-idp

# No TypeScript/SPA frontend today (see insecureapplication-go/z-ai/gallery-idp-plan.md
# section 1) -- this is a placeholder for future UI work so `make build`
# keeps working unchanged if one is added later.
build-frontend:

dev:
	go run ./cmd/gallery-idp -listen :3005

test:
	go test ./...

clean:
	rm -f gallery-idp
	rm -f gallery-idp.sqlite3

install: build
	cp gallery-idp /home/exedev/gallery-idp
	sudo cp gallery-idp.service /etc/systemd/system/gallery-idp.service
	sudo systemctl daemon-reload
	sudo systemctl enable --now gallery-idp

docker-build:
	docker build -t $(IMAGE_NAME) .
