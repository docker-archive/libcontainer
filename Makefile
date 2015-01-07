
all:
	docker build -t dockercore/libcontainer .

test: 
	docker run --rm -it --privileged dockercore/libcontainer make TEST_TAGS="${TEST_TAGS}" direct-test

sh:
	docker run --rm -it --privileged -w /busybox dockercore/libcontainer nsinit exec sh

GO_PACKAGES = $(shell find . -not \( -wholename ./vendor -prune -o -wholename ./.git -prune \) -name '*.go' -print0 | xargs -0n1 dirname | sort -u)

direct-test:
	go test $(TEST_TAGS) -cover -v $(GO_PACKAGES)

direct-test-short:
	go test $(TEST_TAGS) -cover -test.short -v $(GO_PACKAGES)

direct-build:
	go build -v $(GO_PACKAGES)

direct-install:
	go install -v $(GO_PACKAGES)
