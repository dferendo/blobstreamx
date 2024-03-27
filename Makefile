#!/usr/bin/make -f

OPERATOR_DOCKER_IMAGE_NAME := "fuel-infrastructure/fuel-stream-x-operator-docker-e2e"
OPERATOR_DOCKER_IMAGE_TAG := $(shell git rev-parse --short HEAD)
OPERATOR_DOCKER_CONTAINER_NAME := "fuel-stream-x-operator-container"

RELAYER_DOCKER_IMAGE_NAME := "fuel-infrastructure/fuel-stream-x-relayer-docker-e2e"
RELAYER_DOCKER_IMAGE_TAG := $(shell git rev-parse --short HEAD)
RELAYER_DOCKER_CONTAINER_NAME := "fuel-stream-x-relayer-container"

###############################################################################
###                                 Docker                                  ###
###############################################################################

build-operator-docker-image:
	@echo "🤖 Building Operator Docker image..."

	@docker build \
		--tag "${OPERATOR_DOCKER_IMAGE_NAME}:${OPERATOR_DOCKER_IMAGE_TAG}" \
		-f Dockerfile.operator .
	@docker tag ${OPERATOR_DOCKER_IMAGE_NAME}:${OPERATOR_DOCKER_IMAGE_TAG} ${OPERATOR_DOCKER_IMAGE_NAME}:latest
	@echo Successfully tagged ${OPERATOR_DOCKER_IMAGE_NAME}:latest

	@echo "✅ Finished building Operator Docker image!"

build-relayer-docker-image:
	@echo "🤖 Building Relayer Docker image..."

	@docker build \
		--tag "${RELAYER_DOCKER_IMAGE_NAME}:${RELAYER_DOCKER_IMAGE_TAG}" \
		-f Dockerfile.relayer .
	@docker tag ${RELAYER_DOCKER_IMAGE_NAME}:${RELAYER_DOCKER_IMAGE_TAG} ${RELAYER_DOCKER_IMAGE_NAME}:latest
	@echo Successfully tagged ${RELAYER_DOCKER_IMAGE_NAME}:latest

	@echo "✅ Finished building Relayer Docker image!"