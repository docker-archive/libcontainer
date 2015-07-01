FROM golang:1.4

RUN echo "deb http://ftp.us.debian.org/debian testing main contrib" >> /etc/apt/sources.list
RUN apt-get update && apt-get install -y iptables criu=1.5.2-1 git build-essential autoconf libtool && rm -rf /var/lib/apt/lists/*

RUN go get golang.org/x/tools/cmd/cover

ENV GOPATH $GOPATH:/go/src/github.com/docker/libcontainer/vendor
RUN go get github.com/docker/docker/pkg/term

# Need Libseccomp v2.2.1
RUN git clone https://github.com/seccomp/libseccomp /libseccomp
RUN cd /libseccomp && git checkout v2.2.1 && ./autogen.sh && ./configure && make && make check && make install
# Fix linking error
RUN cp /usr/local/lib/libseccomp.so /usr/lib/libseccomp.so.2

# setup a playground for us to spawn containers in
RUN mkdir /busybox && \
    curl -sSL 'https://github.com/jpetazzo/docker-busybox/raw/buildroot-2014.11/rootfs.tar' | tar -xC /busybox

RUN curl -sSL https://raw.githubusercontent.com/docker/docker/master/hack/dind -o /dind && \
    chmod +x /dind

COPY . /go/src/github.com/docker/libcontainer
WORKDIR /go/src/github.com/docker/libcontainer
RUN cp sample_configs/minimal.json /busybox/container.json

RUN make TEST_TAGS='-tags seccomp' direct-install

ENTRYPOINT ["/dind"]
CMD ["make", "TEST_TAGS=-tags seccomp", "direct-test"]
