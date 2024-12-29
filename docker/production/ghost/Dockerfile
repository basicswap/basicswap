FROM i_swapclient as install_stage

RUN basicswap-prepare --preparebinonly --bindir=/coin_bin --withcoin=ghost,particl && \
    find /coin_bin -name *.tar.gz -delete

FROM debian:bullseye-slim
COPY --from=install_stage /coin_bin .

ENV GHOST_DATA /data

RUN groupadd -r ghost && useradd -r -m -g ghost ghost \
    && apt-get update \
    && apt-get install -qq --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p "$GHOST_DATA" \
    && chown -R ghost:ghost "$GHOST_DATA" \
    && ln -sfn "$GHOST_DATA" /home/ghost/.ghost \
    && chown -h ghost:ghost /home/ghost/.ghost
VOLUME /data

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

EXPOSE 51735 20792 51738
CMD ["/ghost/ghostd", "--datadir=/data"]
