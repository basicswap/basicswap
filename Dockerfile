FROM ubuntu:18.10

ENV LANG=C.UTF-8 \
    PARTICL_DATADIR="/coindata/particl" \
    PARTICL_BINDIR="/opt/particl" \
    LITECOIN_BINDIR="/opt/litecoin" \
    DATADIRS="/coindata"

RUN apt-get update; \
    apt-get install -y wget python3-pip curl gnupg unzip protobuf-compiler;

RUN cd ~; \
    wget https://github.com/particl/coldstakepool/archive/master.zip; \
    unzip master.zip; \
    cd coldstakepool-master; \
    pip3 install .; \
    pip3 install pyzmq plyvel protobuf;

RUN PARTICL_VERSION=0.18.0.12 PARTICL_VERSION_TAG= PARTICL_ARCH=x86_64-linux-gnu_nousb.tar.gz coldstakepool-prepare --update_core; \
    wget https://download.litecoin.org/litecoin-0.17.1/linux/litecoin-0.17.1-x86_64-linux-gnu.tar.gz; \
    mkdir -p ${LITECOIN_BINDIR}; \
    tar -xvf litecoin-0.17.1-x86_64-linux-gnu.tar.gz -C ${LITECOIN_BINDIR} --strip-components 2 litecoin-0.17.1/bin/litecoind litecoin-0.17.1/bin/litecoin-cli

# TODO: move coindata dir out of src dir
RUN wget -O bs.zip https://github.com/tecnovert/basicswap/archive/master.zip; \
    unzip bs.zip; \
    cd basicswap-master; \
    protoc -I=basicswap --python_out=basicswap basicswap/messages.proto; \
    pip3 install .;

RUN useradd -ms /bin/bash user; \
    mkdir /coindata  && chown user /coindata

USER user
WORKDIR /home/user

# Expose html port
EXPOSE 12700

VOLUME /coindata

ENTRYPOINT ["basicswap-run", "-datadir=/coindata/basicswap"]
