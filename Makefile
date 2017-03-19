# simple makefile to build and push docker container images
IMAGE_NAME = "sebastianhutter/tikautofw"
COMMIT_ID = ""
# build
# build a new docker image
build_commit:
	docker build -t $(IMAGE_NAME):$(COMMIT_ID) .

# latest
# set the latest tag for the image with the specified nextcloud version tag
build_latest:
	docker build -t $(IMAGE_NAME):latest .

# push the commit tag
push_commit:
	docker push $(IMAGE_NAME):$(COMMIT_ID)

# push the build containers
push_latest:
	docker push $(IMAGE_NAME):latest
