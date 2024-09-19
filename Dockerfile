FROM ubuntu:22.04

ENV LANG=C.UTF-8 \
    DEBIAN_FRONTEND=noninteractive \
    DATADIRS="/coindata"

RUN apt-get update; \
    apt-get install -y wget python3-pip gnupg unzip make g++ autoconf automake libtool pkg-config gosu tzdata;

ARG COINCURVE_VERSION=v0.2
RUN wget -O coincurve-basicswap.zip https://github.com/basicswap/coincurve/archive/refs/tags/basicswap_$COINCURVE_VERSION.zip && \
    echo "c309deef22c929c9ab5b3adf7adbda940bffcea6c6ec7c66202d6c3d4e3ceb79 coincurve-basicswap.zip" | sha256sum -c && \
    unzip coincurve-basicswap.zip && \
    mv ./coincurve-basicswap_$COINCURVE_VERSION ./coincurve-basicswap && \
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
