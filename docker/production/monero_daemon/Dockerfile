FROM i_swapclient AS install_stage

RUN basicswap-prepare --preparebinonly --bindir=/coin_bin --withcoin=monero --withoutcoins=particl

FROM debian:trixie-slim

COPY --from=install_stage /coin_bin .

ENV MONERO_DATA=/data

RUN groupadd -g 1000 monero && useradd -u 1000 -m -g monero monero \
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

CMD ["/monero/monerod", "--non-interactive", "--config-file=/home/monero/.monero/monerod.conf", "--confirm-external-bind"]
