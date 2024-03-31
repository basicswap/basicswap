FROM i_wownero_daemon

ENV WOWNERO_DATA /data

RUN groupadd -r wownero_wallet && useradd -r -m -g wownero_wallet wownero_wallet \
    && apt-get update \
    && apt-get install -qq --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p "$WOWNERO_DATA" \
    && chown -R wownero_wallet:wownero_wallet "$WOWNERO_DATA"
VOLUME $WOWNERO_DATA

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

CMD ["/wownero/wownero-wallet-rpc", "--non-interactive", "--config-file=/data/wownero-wallet-rpc.conf", "--confirm-external-bind"]
