FROM i_swapclient as install_stage

RUN basicswap-prepare --preparebinonly --bindir=/coin_bin --withcoin=litecoin --withoutcoin=particl

FROM debian:buster-slim
COPY --from=install_stage /coin_bin .

ENV LITECOIN_DATA /data

RUN groupadd -r particl && useradd -r -m -g litecoin litecoin \
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
CMD ["litecoind"]
