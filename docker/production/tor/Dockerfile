FROM alpine:latest

# 9050      SOCKS port
# 9051      control port
# 5353      DNS port
EXPOSE 9050 9051 5353
# The tor package keeps an existing tor user
RUN addgroup -g 1000 tor && \
    adduser -D -H -u 1000 -h /var/lib/tor -s /sbin/nologin -G tor tor && \
    apk add --no-cache tor su-exec

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

CMD ["tor", "-f", "/etc/tor/torrc", "--DataDirectory", "/var/lib/tor"]
