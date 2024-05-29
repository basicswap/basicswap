FROM debian:bullseye-slim

ENV LANG=C.UTF-8 \
    DEBIAN_FRONTEND=noninteractive \
    DATADIR=/data

RUN apt-get update; \
    apt-get install -y wget python3-pip gnupg unzip make g++ autoconf automake libtool pkg-config gosu tzdata;

ARG COINCURVE_VERSION=v0.2
RUN wget -O coincurve-anonswap.zip https://github.com/tecnovert/coincurve/archive/refs/tags/anonswap_$COINCURVE_VERSION.zip && \
    unzip coincurve-anonswap.zip && \
    mv ./coincurve-anonswap_$COINCURVE_VERSION ./coincurve-anonswap && \
    cd coincurve-anonswap && \
    python3 setup.py install --force

ARG BASICSWAP_URL=https://github.com/tecnovert/basicswap/archive/master.zip
ARG BASICSWAP_DIR=basicswap-master
RUN wget -O basicswap-repo.zip $BASICSWAP_URL; \
    unzip basicswap-repo.zip; \
    mv $BASICSWAP_DIR /basicswap; \
    cd /basicswap; \
    pip3 install .;

#COPY ./test_code basicswap
#RUN cd basicswap; \
#    pip3 install .;

RUN groupadd -r swap_user && useradd -g swap_user -ms /bin/bash swap_user && \
    mkdir /data && chown swap_user -R /data

VOLUME /data

COPY ./entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["basicswap-run", "-datadir=/data"]
