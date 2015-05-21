FROM debian:jessie

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
    libdbus-1-dev

COPY . /libct
WORKDIR /libct

# build libnl
RUN git submodule update --init && \
    cd .shipped/libnl && \
    ./autogen.sh && \
    ./configure && make -j $(nproc)

RUN make clean && make -j $(nproc)
