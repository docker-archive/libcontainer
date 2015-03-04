FROM golang:1.4

RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libtool \
    autoconf \
    git-core \
    bison \
    flex \
    libselinux1-dev \
    libapparmor-dev \
    libgcc-4.8-dev \
    libnl-3-dev \
    libnl-route-3-dev \
    libdbus-1-dev

RUN go get golang.org/x/tools/cmd/cover

ENV GOPATH $GOPATH:/go/src/github.com/docker/libcontainer/vendor
RUN go get github.com/docker/docker/pkg/term

# setup a playground for us to spawn containers in
RUN mkdir /busybox && \
    curl -sSL 'https://github.com/jpetazzo/docker-busybox/raw/buildroot-2014.11/rootfs.tar' | tar -xC /busybox

RUN curl -sSL https://raw.githubusercontent.com/docker/docker/master/hack/dind -o /dind && \
    chmod +x /dind

COPY vendor/src/github.com/avagin/libct /go/src/github.com/docker/libcontainer/vendor/src/github.com/avagin/libct
RUN make -C /go/src/github.com/docker/libcontainer/vendor/src/github.com/avagin/libct

COPY . /go/src/github.com/docker/libcontainer
WORKDIR /go/src/github.com/docker/libcontainer

RUN cp sample_configs/minimal.json /busybox/container.json

ENV LIBRARY_PATH /go/src/github.com/docker/libcontainer/vendor/src/github.com/avagin/libct/
ENV CGO_LDFLAGS -l:libct.a -l:libnl-route-3.a -l:libnl-3.a -l:libapparmor.a -l:libselinux.a -l:libdbus-1.a -lm
RUN go get -d -v ./...
RUN make direct-install

ENTRYPOINT ["/dind"]
CMD ["make", "direct-test"]
