FROM i_swapclient as install_stage

RUN basicswap-prepare --preparebinonly --bindir=/coin_bin --withcoin=wownero --withoutcoins=particl

FROM debian:bullseye-slim

COPY --from=install_stage /coin_bin .

ENV WOWNERO_DATA /data

RUN groupadd -r wownero && useradd -r -m -g wownero wownero \
    && apt-get update \
    && apt-get install -qq --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p "$WOWNERO_DATA" \
    && chown -R wownero:wownero "$WOWNERO_DATA" \
    && ln -sfn "$WOWNERO_DATA" /home/wownero/.wownero \
    && chown -h wownero:wownero /home/wownero/.wownero
VOLUME $WOWNERO_DATA

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

CMD ["/wownero/wownerod", "--non-interactive", "--config-file=/home/wownero/.wownero/wownerod.conf", "--confirm-external-bind"]
