# https://github.com/NicolasDorier/docker-bitcoin/blob/master/README.md

FROM i_swapclient AS install_stage

RUN basicswap-prepare --preparebinonly --bindir=/coin_bin --withcoin=bitcoincash --withoutcoins=particl && \
    find /coin_bin -name *.tar.gz -delete && \
    chmod -R a+rX /coin_bin

FROM debian:trixie-slim
COPY --from=install_stage /coin_bin .

ENV BITCOINCASH_DATA=/data

RUN groupadd -g 1000 bitcoincash && useradd -u 1000 -m -g bitcoincash bitcoincash \
    && apt-get update \
    && apt-get install -qq --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir "$BITCOINCASH_DATA" \
    && chown -R bitcoincash:bitcoincash "$BITCOINCASH_DATA" \
    && ln -sfn "$BITCOINCASH_DATA" /home/bitcoincash/.bitcoincash \
    && chown -h bitcoincash:bitcoincash /home/bitcoincash/.bitcoincash
VOLUME /data

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

EXPOSE 8332 8333 18332 18333 18443 18444
CMD ["/bitcoincash/bitcoind", "--datadir=/data"]
