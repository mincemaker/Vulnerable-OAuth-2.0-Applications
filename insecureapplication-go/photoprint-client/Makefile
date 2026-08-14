-include .env
IMAGE_NAME ?= photoprint-client:latest

.PHONY: build dev test clean install docker-build

build:
	go build -o photoprint-client ./cmd/photoprint-client

dev:
	go run ./cmd/photoprint-client -listen :3000

test:
	go test ./...

clean:
	rm -f photoprint-client

install: build
	cp photoprint-client /home/exedev/photoprint-client
	sudo cp photoprint-client.service /etc/systemd/system/photoprint-client.service
	sudo systemctl daemon-reload
	sudo systemctl enable --now photoprint-client

docker-build:
	docker build -t $(IMAGE_NAME) .
