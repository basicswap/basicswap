FROM i_swapclient AS install_stage

RUN basicswap-prepare --preparebinonly --bindir=/coin_bin --withcoin=litecoin --withoutcoin=particl && \
    find /coin_bin -name *.tar.gz -delete && \
    chmod -R a+rX /coin_bin

FROM debian:trixie-slim
COPY --from=install_stage /coin_bin .

ENV LITECOIN_DATA=/data

RUN groupadd -g 1000 litecoin && useradd -u 1000 -m -g litecoin litecoin \
    && apt-get update \
    && apt-get install -qq --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir "$LITECOIN_DATA" \
    && chown -R litecoin:litecoin "$LITECOIN_DATA" \
    && ln -sfn "$LITECOIN_DATA" /home/litecoin/.litecoin \
    && chown -h litecoin:litecoin /home/litecoin/.litecoin
VOLUME /data

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

EXPOSE 8332 8333 18332 18333 18443 18444
CMD ["/litecoin/litecoind", "--datadir=/data"]
