IMAGE       = iam-eks-group-mapper
VERSION     = 2.0.0
REPOSITORY ?= ldoming

all: build push

build:
	@docker build --pull --rm -t $(IMAGE):$(VERSION) .
	@docker tag $(IMAGE):$(VERSION) $(IMAGE):latest

push:
	@docker tag $(IMAGE):$(VERSION) $(REPOSITORY)/$(IMAGE):$(VERSION)
	@DOCKER_CONTENT_TRUST=1 docker push $(REPOSITORY)/$(IMAGE):$(VERSION)
	@docker tag $(IMAGE):$(VERSION) $(REPOSITORY)/$(IMAGE):latest
	@DOCKER_CONTENT_TRUST=1 docker push $(REPOSITORY)/$(IMAGE):latest

run: build
	@docker-compose up