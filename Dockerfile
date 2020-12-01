FROM ubuntu:20.04

ARG WITH_COINS
ARG WITHOUT_COINS

ENV LANG=C.UTF-8 \
    DEBIAN_FRONTEND=noninteractive \
    DATADIRS="/coindata"

RUN apt-get update; \
    apt-get install -y wget python3-pip gnupg unzip protobuf-compiler automake libtool pkg-config;

RUN wget -O coincurve-anonswap.zip https://github.com/tecnovert/coincurve/archive/anonswap.zip && \
    unzip coincurve-anonswap.zip && \
    cd coincurve-anonswap && \
    python3 setup.py install --force

# TODO: move coindata dir out of src dir
COPY . basicswap-master
RUN cd basicswap-master; \
    protoc -I=basicswap --python_out=basicswap basicswap/messages.proto; \
    pip3 install .;

# Download binaries, these will be part of the docker image
RUN basicswap-prepare -datadir=/opt -preparebinonly ${WITH_COINS} ${WITHOUT_COINS}

RUN useradd -ms /bin/bash user && \
    mkdir /coindata && chown user -R /coindata

USER user
WORKDIR /home/user

# Expose html port
EXPOSE 12700

VOLUME /coindata

ENTRYPOINT ["basicswap-run", "-datadir=/coindata/basicswap"]
