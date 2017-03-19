# simple makefile to build and push docker container images
IMAGE_NAME = "sebastianhutter/tikautofw"
IMAGE_VERSION = "0.0.1"
# build
# build a new docker image
.PHONY: build
build:
	docker build -t $(IMAGE_NAME):$(IMAGE_VERSION) .

# latest
# set the latest tag for the image with the specified nextcloud version tag
.PHONY: latest
latest:
	docker build -t $(IMAGE_NAME):latest .
# push the build containers
.PHONY: push_latest
push:
		docker push $(IMAGE_NAME):latest
