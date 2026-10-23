FROM i_decred_daemon

ENV DCR_DATA=/data

VOLUME /data

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

EXPOSE 9209
CMD ["/decred/dcrwallet", "--datadir=/data"]
