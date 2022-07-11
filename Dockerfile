FROM ubuntu:22.04

ENV LANG=C.UTF-8 \
    DEBIAN_FRONTEND=noninteractive \
    DATADIRS="/coindata"

RUN apt-get update; \
    apt-get install -y wget python3-pip gnupg unzip make g++ autoconf automake libtool pkg-config gosu tzdata;

# Must install protoc directly as latest package is only on 3.12
RUN wget -O protobuf_src.tar.gz https://github.com/protocolbuffers/protobuf/releases/download/v21.1/protobuf-python-4.21.1.tar.gz && \
    tar xvf protobuf_src.tar.gz && \
    cd protobuf-3.21.1 && \
    ./configure --prefix=/usr && \
    make -j$(nproc) install && \
    ldconfig

ARG COINCURVE_VERSION=v0.1
RUN wget -O coincurve-anonswap.zip https://github.com/tecnovert/coincurve/archive/refs/tags/anonswap_$COINCURVE_VERSION.zip && \
    unzip coincurve-anonswap.zip && \
    mv ./coincurve-anonswap_$COINCURVE_VERSION ./coincurve-anonswap && \
    cd coincurve-anonswap && \
    python3 setup.py install --force

# Install requirements first so as to skip in subsequent rebuilds
COPY ./requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY . basicswap-master
RUN cd basicswap-master; \
    protoc -I=basicswap --python_out=basicswap basicswap/messages.proto; \
    pip3 install .;

RUN useradd -ms /bin/bash swap_user && \
    mkdir /coindata && chown swap_user -R /coindata

# Expose html port
EXPOSE 12700

VOLUME /coindata

COPY ./docker/entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["basicswap-run", "-datadir=/coindata"]
