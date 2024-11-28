FROM i_swapclient as install_stage

RUN basicswap-prepare --preparebinonly --bindir=/coin_bin --withcoin=dogecoin --withoutcoin=particl && \
    find /coin_bin -name *.tar.gz -delete

FROM debian:bullseye-slim
COPY --from=install_stage /coin_bin .

ENV DOGECOIN_DATA /data

RUN groupadd -r dogecoin && useradd -r -m -g dogecoin dogecoin \
    && apt-get update \
    && apt-get install -qq --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir "$DOGECOIN_DATA" \
    && chown -R dogecoin:dogecoin "$DOGECOIN_DATA" \
    && ln -sfn "$DOGECOIN_DATA" /home/dogecoin/.dogecoin \
    && chown -h dogecoin:dogecoin /home/dogecoin/.dogecoin
VOLUME /data

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

EXPOSE 8332 8333 18332 18333 18443 18444
CMD ["/dogecoin/dogecoind", "--datadir=/data"]
