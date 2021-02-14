FROM ubuntu:20.04

ENV LANG=C.UTF-8 \
    DEBIAN_FRONTEND=noninteractive \
    DATADIRS="/coindata"

RUN apt-get update; \
    apt-get install -y wget python3-pip gnupg unzip protobuf-compiler automake libtool pkg-config gosu tzdata;

RUN wget -O coincurve-anonswap.zip https://github.com/tecnovert/coincurve/archive/anonswap.zip && \
    unzip coincurve-anonswap.zip && \
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
