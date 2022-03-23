FROM alpine:latest

# 9050      SOCKS port
# 9051      control port
# 5353      DNS port
EXPOSE 9050 9051 5353
RUN apk add --no-cache tor
CMD tor -f /etc/tor/torrc
