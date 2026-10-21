FROM i_swapclient AS install_stage

RUN basicswap-prepare --preparebinonly --bindir=/coin_bin --withcoin=decred --withoutcoins=particl && \
    find /coin_bin -name *.tar.gz -delete && \
    chmod -R a+rX /coin_bin

FROM debian:trixie-slim
COPY --from=install_stage /coin_bin .

ENV DCR_DATA=/data

RUN groupadd -g 1000 decred && useradd -u 1000 -m -g decred decred \
    && apt-get update \
    && apt-get install -qq --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir "$DCR_DATA" \
    && chown -R decred:decred "$DCR_DATA" \
    && ln -sfn "$DCR_DATA" /home/decred/decred \
    && chown -h decred:decred /home/decred/decred
VOLUME /data

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

EXPOSE 9108 9109
CMD ["/decred/dcrd", "--datadir=/data"]
