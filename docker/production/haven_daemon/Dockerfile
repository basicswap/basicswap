FROM i_swapclient as install_stage

RUN basicswap-prepare --preparebinonly --bindir=/coin_bin --withcoin=haven --withoutcoins=particl

FROM debian:bullseye-slim

COPY --from=install_stage /coin_bin .

ENV HAVEN_DATA /data

RUN groupadd -r haven && useradd -r -m -g haven haven \
    && apt-get update \
    && apt-get install -qq --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p "$HAVEN_DATA" \
    && chown -R haven:haven "$HAVEN_DATA" \
    && ln -sfn "$HAVEN_DATA" /home/haven/.haven \
    && chown -h haven:haven /home/haven/.haven
VOLUME $HAVEN_DATA

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

CMD ["/haven/havend", "--non-interactive", "--config-file=/home/haven/.haven/havend.conf", "--confirm-external-bind"]
