FROM debian:buster-slim

ENV LANG=C.UTF-8 \
    DEBIAN_FRONTEND=noninteractive \
    DATADIR=/data

RUN apt-get update; \
    apt-get install -y wget python3-pip gnupg unzip protobuf-compiler automake libtool pkg-config gosu;

RUN wget -O coincurve-anonswap.zip https://github.com/tecnovert/coincurve/archive/anonswap.zip && \
    unzip coincurve-anonswap.zip && \
    cd coincurve-anonswap && \
    python3 setup.py install --force

RUN wget -O basicswap-master.zip https://github.com/tecnovert/basicswap/archive/master.zip; \
    unzip basicswap-master.zip; \
    cd basicswap-master; \
    protoc -I=basicswap --python_out=basicswap basicswap/messages.proto; \
    pip3 install .;

RUN useradd -ms /bin/bash swap_user && \
    mkdir /data && chown swap_user -R /data

# Expose html port
EXPOSE 12700

VOLUME /data

COPY ./entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["basicswap-run", "-datadir=/data"]
