FROM ubuntu:18.10

ENV LANG=C.UTF-8 \
    DATADIRS="/coindata"

RUN apt-get update; \
    apt-get install -y wget python3-pip gnupg unzip protobuf-compiler;

# TODO: move coindata dir out of src dir
COPY . basicswap-master
RUN cd basicswap-master; \
    protoc -I=basicswap --python_out=basicswap basicswap/messages.proto; \
    pip3 install .;

# Download binaries, these will be part of the docker image
RUN basicswap-prepare -datadir=/opt -preparebinonly

RUN useradd -ms /bin/bash user && \
    mkdir /coindata && chown user -R /coindata

USER user
WORKDIR /home/user

# Expose html port
EXPOSE 12700

VOLUME /coindata

ENTRYPOINT ["basicswap-run", "-datadir=/coindata/basicswap"]
