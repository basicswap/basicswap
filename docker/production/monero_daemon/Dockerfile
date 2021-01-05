FROM i_swapclient as install_stage

RUN basicswap-prepare --preparebinonly --bindir=/coin_bin --withcoin=monero --withoutcoins=particl

FROM debian:buster-slim

COPY --from=install_stage /coin_bin .

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
CMD ["monerod", "--non-interactive", "--config-file=/home/monero/.monero/monerod.conf"]
