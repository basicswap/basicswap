FROM i_monero_daemon

ENV MONERO_DATA /data

RUN groupadd -r monero && useradd -r -m -g monero monero \
    && apt-get update \
    && apt-get install -qq --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p "$MONERO_DATA" \
    && chown -R monero:monero "$MONERO_DATA" \
    && ln -sfn "$MONERO_DATA" /home/monero/.monero \
    && chown -h monero:monero /home/monero/.monero
VOLUME $MONERO_DATA

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

EXPOSE 18080
CMD ["monero-wallet-rpc", "--config-file=/home/monero/.monero/monerod.conf"]
