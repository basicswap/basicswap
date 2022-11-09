# https://github.com/NicolasDorier/docker-bitcoin/blob/master/README.md

FROM i_swapclient as install_stage

RUN basicswap-prepare --preparebinonly --bindir=/coin_bin --withcoin=dash --withoutcoins=particl && \
    find /coin_bin -name *.tar.gz -delete

FROM debian:bullseye-slim
COPY --from=install_stage /coin_bin .

ENV DASH_DATA /data

RUN groupadd -r dash && useradd -r -m -g dash dash \
    && apt-get update \
    && apt-get install -qq --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir "$DASH_DATA" \
    && chown -R dash:dash "$DASH_DATA" \
    && ln -sfn "$DASH_DATA" /home/dash/.dash \
    && chown -h dash:dash /home/dash/.dash
VOLUME /data

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

EXPOSE 9999 9998
CMD ["/dash/dashd", "--datadir=/data"]
