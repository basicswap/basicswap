FROM i_decred_daemon

ENV DCR_DATA /data

RUN groupadd -r decred && useradd -r -m -g decred decred \
    && apt-get update \
    && apt-get install -qq --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir "$DCR_DATA" \
    && chown -R decred:decred "$DCR_DATA" \
    && ln -sfn "$DECRED_DATA" /home/decred/decred \
    && chown -h decred:decred /home/decred/decred
VOLUME /data

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

EXPOSE 9209
CMD ["/decred/dcrwallet", "--datadir=/data"]
