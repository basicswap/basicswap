# Zephyr wallet-rpc image - mirrors docker/production/wownero_wallet, built FROM the zephyr daemon
# image (which carries the project-built binaries; see ../zephyr_daemon/Dockerfile and BUILD-NOTES.md).

FROM i_zephyr_daemon

ENV ZEPHYR_DATA /data

RUN groupadd -r zephyr_wallet && useradd -r -m -g zephyr_wallet zephyr_wallet \
    && apt-get update \
    && apt-get install -qq --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p "$ZEPHYR_DATA" \
    && chown -R zephyr_wallet:zephyr_wallet "$ZEPHYR_DATA"
VOLUME $ZEPHYR_DATA

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

CMD ["/zephyr/zephyr-wallet-rpc", "--config-file=/data/zephyr-wallet-rpc.conf", "--confirm-external-bind"]
