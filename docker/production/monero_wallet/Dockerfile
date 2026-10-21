FROM i_monero_daemon

ENV MONERO_DATA=/data

VOLUME $MONERO_DATA

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

CMD ["/monero/monero-wallet-rpc", "--config-file=/data/monero_wallet.conf", "--confirm-external-bind"]
