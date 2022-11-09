FROM i_swapclient as install_stage

RUN basicswap-prepare --preparebinonly --bindir=/coin_bin --withcoin=pivx --withoutcoins=particl && \
    find /coin_bin -name *.tar.gz -delete

FROM debian:bullseye-slim
COPY --from=install_stage /coin_bin .

ENV PIVX_DATA /data

RUN groupadd -r pivx && useradd -r -m -g pivx pivx \
    && apt-get update \
    && apt-get install -qq --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir "$PIVX_DATA" \
    && chown -R pivx:pivx "$PIVX_DATA" \
    && ln -sfn "$PIVX_DATA" /home/pivx/.pivx \
    && chown -h pivx:pivx /home/pivx/.pivx
VOLUME /data

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

EXPOSE 51472 51473
CMD ["/pivx/pivxd", "--datadir=/data"]
