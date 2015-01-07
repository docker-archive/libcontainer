FROM golang:1.4

RUN apt-get install -y libseccomp2 libseccomp-dev
RUN go get golang.org/x/tools/cmd/cover

ENV GOPATH $GOPATH:/go/src/github.com/docker/libcontainer/vendor
RUN go get github.com/docker/docker/pkg/term

# setup a playground for us to spawn containers in
RUN mkdir /busybox && \
    curl -sSL 'https://github.com/jpetazzo/docker-busybox/raw/buildroot-2014.02/rootfs.tar' | tar -xC /busybox

RUN curl -sSL https://raw.githubusercontent.com/docker/docker/master/project/dind -o /dind && \
    chmod +x /dind

COPY . /go/src/github.com/docker/libcontainer
WORKDIR /go/src/github.com/docker/libcontainer
RUN cp sample_configs/minimal.json /busybox/container.json

RUN go get -d -v ./...
RUN  TEST_TAGS="-tag seccomp" make direct-install

ENTRYPOINT ["/dind"]
CMD ["make", "TEST_TAGS=\"-tag seccomp\"", "direct-test"]
