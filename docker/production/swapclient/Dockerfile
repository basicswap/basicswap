FROM debian:trixie-slim AS builder

ENV LANG=C.UTF-8 \
    DEBIAN_FRONTEND=noninteractive \
    VIRTUAL_ENV=/opt/venv

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates git python3-pip libpython3-dev python3-venv pkg-config gcc libc-dev cmake ninja-build

# Create python venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

ARG BASICSWAP_REPO=https://github.com/basicswap/basicswap.git
ARG BASICSWAP_COMMIT=277b46b0278f1cc76199f7e847988647a1b36e38
RUN git init -q /basicswap && \
    cd /basicswap && \
    git fetch -q --depth 1 "$BASICSWAP_REPO" "$BASICSWAP_COMMIT" && \
    git checkout -q --detach FETCH_HEAD && \
    test "$(git rev-parse HEAD)" = "$BASICSWAP_COMMIT" && \
    rm -rf .git && \
    pip3 install -r requirements.txt --require-hashes && \
    pip3 install .

FROM debian:trixie-slim

ENV LANG=C.UTF-8 \
    DEBIAN_FRONTEND=noninteractive \
    DATADIR=/data \
    VIRTUAL_ENV=/opt/venv

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates gnupg gosu procps python3 tzdata && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /basicswap /basicswap
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

RUN groupadd -r swap_user && useradd -g swap_user -ms /bin/bash swap_user && \
    mkdir /data && chown swap_user -R /data

VOLUME /data

COPY ./entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["basicswap-run", "-datadir=/data"]
