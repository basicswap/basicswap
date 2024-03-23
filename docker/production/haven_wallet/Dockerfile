FROM i_haven_daemon

ENV HAVEN_DATA /data

RUN groupadd -r haven_wallet && useradd -r -m -g haven_wallet haven_wallet \
    && apt-get update \
    && apt-get install -qq --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p "$HAVEN_DATA" \
    && chown -R haven_wallet:haven_wallet "$HAVEN_DATA"
VOLUME $HAVEN_DATA

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

CMD ["/haven/haven-wallet-rpc", "--non-interactive", "--config-file=/data/haven_wallet.conf", "--confirm-external-bind"]
