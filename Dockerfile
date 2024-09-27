FROM ubuntu:22.04

ENV LANG=C.UTF-8 \
    DEBIAN_FRONTEND=noninteractive \
    DATADIRS="/coindata"

RUN apt-get update; \
    apt-get install -y git python3-pip gnupg make g++ autoconf automake libtool pkg-config gosu tzdata;

ARG COINCURVE_VERSION=v0.2
RUN git clone https://github.com/basicswap/coincurve.git -b basicswap_$COINCURVE_VERSION coincurve-basicswap && \
    cd coincurve-basicswap && \
    pip install .

# Install requirements first so as to skip in subsequent rebuilds
COPY ./requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY . basicswap-master
RUN cd basicswap-master; \
    pip3 install .;

RUN useradd -ms /bin/bash swap_user && \
    mkdir /coindata && chown swap_user -R /coindata

# html port
EXPOSE 12700
# websocket port
EXPOSE 11700

VOLUME /coindata

COPY ./docker/entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["basicswap-run", "-datadir=/coindata"]
