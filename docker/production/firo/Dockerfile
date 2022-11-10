FROM i_swapclient as install_stage

RUN basicswap-prepare --preparebinonly --bindir=/coin_bin --withcoin=firo --withoutcoins=particl && \
    find /coin_bin -name *.tar.gz -delete

FROM debian:bullseye-slim
COPY --from=install_stage /coin_bin .

ENV FIRO_DATA /data

RUN groupadd -r firo && useradd -r -m -g firo firo \
    && apt-get update \
    && apt-get install -qq --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir "$FIRO_DATA" \
    && chown -R firo:firo "$FIRO_DATA" \
    && ln -sfn "$FIRO_DATA" /home/firo/.firo \
    && chown -h firo:firo /home/firo/.firo
VOLUME /data

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

EXPOSE 8168 8888
CMD ["/firo/firod", "--datadir=/data"]
