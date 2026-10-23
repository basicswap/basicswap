FROM i_swapclient AS install_stage

RUN basicswap-prepare --preparebinonly --bindir=/coin_bin --withcoin=particl && \
    find /coin_bin -name *.tar.gz -delete && \
    chmod -R a+rX /coin_bin

FROM debian:trixie-slim
COPY --from=install_stage /coin_bin .

ENV PARTICL_DATA=/data

RUN groupadd -g 1000 particl && useradd -u 1000 -m -g particl particl \
    && apt-get update \
    && apt-get install -qq --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p "$PARTICL_DATA" \
    && chown -R particl:particl "$PARTICL_DATA" \
    && ln -sfn "$PARTICL_DATA" /home/particl/.particl \
    && chown -h particl:particl /home/particl/.particl
VOLUME /data

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

EXPOSE 51735 20792 51738
CMD ["/particl/particld", "--datadir=/data"]
