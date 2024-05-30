FROM i_swapclient as install_stage

RUN basicswap-prepare --preparebinonly --bindir=/coin_bin --withcoin=decred --withoutcoins=particl && \
    find /coin_bin -name *.tar.gz -delete

FROM debian:bullseye-slim
COPY --from=install_stage /coin_bin .

ENV DCR_DATA /data

RUN groupadd -r decred && useradd -r -m -g decred decred \
    && apt-get update \
    && apt-get install -qq --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir "$DCR_DATA" \
    && chown -R decred:decred "$DCR_DATA" \
    && ln -sfn "$DECRED_DATA" /home/decred/decred \
    && chown -h decred:decred /home/decred/decred
VOLUME /data

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

EXPOSE 9108 9109
CMD ["/decred/dcrd", "--datadir=/data"]
