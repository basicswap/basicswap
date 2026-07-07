# Zephyr daemon image for a BasicSwap production deployment. Mirrors docker/production/wownero_daemon
# (same user/volume/entrypoint shape), with ONE required adaptation: Wownero pulls its release binary
# via `basicswap-prepare --withcoin=wownero`, but Zephyr has no downloadable signed release - zephyrd
# is built from source on an Ubuntu-20.04 toolchain (see zephyr-testnet/BUILD-NOTES.md, it will not
# build on a 2026 gcc/Boost). So this image COPIES the project-built binaries instead of downloading.
#
# Build context must contain ./coin_bin/{zephyrd,zephyr-wallet-rpc} (copy them from work/bin/ produced
# by zephyr-testnet/scripts/build-zephyr-patched.sh). To reach full Wownero parity later, wire Zephyr
# into bin/basicswap_prepare.py with a signed release URL + hash and a PGP key (see P3 in
# zephyr-testnet/WOWNERO-PARITY-PLAN.md), then this can FROM i_swapclient + prepare like Wownero.

FROM debian:bullseye-slim

COPY coin_bin/ .

ENV ZEPHYR_DATA /data

RUN groupadd -r zephyr && useradd -r -m -g zephyr zephyr \
    && apt-get update \
    && apt-get install -qq --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p "$ZEPHYR_DATA" \
    && chown -R zephyr:zephyr "$ZEPHYR_DATA" \
    && ln -sfn "$ZEPHYR_DATA" /home/zephyr/.zephyr \
    && chown -h zephyr:zephyr /home/zephyr/.zephyr
VOLUME $ZEPHYR_DATA

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

CMD ["/zephyr/zephyrd", "--non-interactive", "--config-file=/home/zephyr/.zephyr/zephyrd.conf", "--confirm-external-bind"]
