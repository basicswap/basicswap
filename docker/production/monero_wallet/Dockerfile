FROM i_monero_daemon

ENV MONERO_DATA /data

RUN groupadd -r monero_wallet && useradd -r -m -g monero_wallet monero_wallet \
    && apt-get update \
    && apt-get install -qq --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p "$MONERO_DATA" \
    && chown -R monero_wallet:monero_wallet "$MONERO_DATA"
VOLUME $MONERO_DATA

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

CMD ["/monero/monero-wallet-rpc", "--non-interactive", "--config-file=/data/monero_wallet.conf", "--confirm-external-bind"]
