BUILD_VERSION=0.0.1
TARGET=target
REPOSITORY=github.com/larwef/papers-please

all:
	make build
	make docker

# ----------------------------------- Proto -----------------------------------
.PHONY: proto
proto: proto-lint proto-generate

proto-generate:
	(cd api && buf generate)

proto-lint:
	(cd api && buf lint)

proto-mod-update:
	(cd api && buf mod update)

# ------------------------------------- Go -------------------------------------
.PHONY: build
build:
	make build-app APP=server 
	make build-app APP=client

build-app:
	GOOS=linux GOARCH=arm GOARM=7 go build \
		-ldflags "-X main.version=$(BUILD_VERSION)" \
		-o $(TARGET)/$(APP).bin cmd/$(APP)/main.go

run-client:
	CLIENT_GREETER_ADDR=localhost:8081 \
	CLIENT_NAME=Lars \
	go run cmd/client/main.go

# ---------------------------------- Docker -----------------------------------
.PHONY: docker
docker:
	make docker-build-app APP=server
	make docker-build-app APP=client

docker-build-app:
	docker build -t $(REPOSITORY)/$(APP):$(BUILD_VERSION) \
		--build-arg target=$(TARGET)/$(APP).bin -f build/package/Dockerfile .

compose-up:
	VERSION=$(BUILD_VERSION) \
	SERVER_PORT=8081 \
	CLIENT_PORT=8082 \
		docker compose -f deployments/docker-compose/docker-compose.yml up

compose-down:
	VERSION=$(BUILD_VERSION) \
	SERVER_PORT=8081 \
	CLIENT_PORT=8082 \
		docker compose -f deployments/docker-compose/docker-compose.yml down