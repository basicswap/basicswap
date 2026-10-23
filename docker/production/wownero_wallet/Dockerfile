FROM i_wownero_daemon

ENV WOWNERO_DATA=/data

VOLUME $WOWNERO_DATA

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

CMD ["/wownero/wownero-wallet-rpc", "--config-file=/data/wownero-wallet-rpc.conf", "--confirm-external-bind"]
