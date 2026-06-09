FROM debian:trixie-slim

ENV LANG=C.UTF-8 \
    DEBIAN_FRONTEND=noninteractive \
    DATADIRS="/coindata" \
    VIRTUAL_ENV=/opt/venv

RUN apt-get update; \
    apt-get install -y --no-install-recommends \
        python3-pip libpython3-dev python3-venv gnupg pkg-config gcc libc-dev gosu tzdata cmake ninja-build;

# Create python venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Install requirements first so as to skip in subsequent rebuilds
COPY ./requirements.txt requirements.txt
RUN pip install -r requirements.txt --require-hashes

COPY . basicswap-master
RUN cd basicswap-master; \
    pip install .;

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
