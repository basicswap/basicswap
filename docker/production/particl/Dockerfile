FROM i_swapclient as install_stage

RUN basicswap-prepare --preparebinonly --bindir=/coin_bin --withcoin=particl

FROM debian:buster-slim
COPY --from=install_stage /coin_bin .

ENV PARTICL_DATA /data

RUN groupadd -r particl && useradd -r -m -g particl particl \
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
CMD ["particld"]
