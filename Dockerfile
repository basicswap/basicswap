FROM ubuntu:18.10

ENV LANG=C.UTF-8 \
    PARTICL_DATADIR="/coindata/particl" \
    PARTICL_BINDIR="/opt/particl" \
    LITECOIN_BINDIR="/opt/litecoin" \
    LITECOIN_VERSION="0.17.1" \
    DATADIRS="/coindata"

RUN apt-get update; \
    apt-get install -y wget python3-pip curl gnupg unzip protobuf-compiler;

RUN cd ~; \
    wget https://github.com/particl/coldstakepool/archive/master.zip; \
    unzip master.zip; \
    cd coldstakepool-master; \
    pip3 install .; \
    pip3 install pyzmq plyvel protobuf;

RUN PARTICL_VERSION=0.18.0.12 PARTICL_VERSION_TAG= PARTICL_ARCH=x86_64-linux-gnu_nousb.tar.gz coldstakepool-prepare --update_core && \
    mkdir -p ${LITECOIN_BINDIR} && cd ${LITECOIN_BINDIR} && \
    wget https://download.litecoin.org/litecoin-${LITECOIN_VERSION}/linux/litecoin-${LITECOIN_VERSION}-x86_64-linux-gnu.tar.gz && \
    wget -O build.assert https://github.com/litecoin-project/gitian.sigs.ltc/raw/master/${LITECOIN_VERSION}-linux/thrasher/litecoin-linux-0.17-build.assert && \
    wget -O build.assert.sig https://github.com/litecoin-project/gitian.sigs.ltc/raw/master/${LITECOIN_VERSION}-linux/thrasher/litecoin-linux-0.17-build.assert.sig && \
    wget -qO - https://raw.githubusercontent.com/litecoin-project/litecoin/master/contrib/gitian-keys/thrasher-key.pgp | gpg --import - && \
    gpg --verify build.assert.sig build.assert && \
    grep " litecoin-${LITECOIN_VERSION}-x86_64-linux-gnu.tar.gz\$" build.assert | sha256sum -c - && \
    tar -xvf litecoin-${LITECOIN_VERSION}-x86_64-linux-gnu.tar.gz -C ${LITECOIN_BINDIR} --strip-components 2 litecoin-${LITECOIN_VERSION}/bin/litecoind litecoin-${LITECOIN_VERSION}/bin/litecoin-cli && \
    rm litecoin-${LITECOIN_VERSION}-x86_64-linux-gnu.tar.gz && rm *.assert*

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
