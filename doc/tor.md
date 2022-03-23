## Tor

Basicswap can be configured to route all traffic through a tor proxy.


### basicswap-prepare

basicswap-prepare can be configured to download all binaries through tor and to enable or disable tor in all active coin config files.


#### For a new install

Note that some download links, notably for Litecoin, are unreachable when using tor.

If running through docker start the tor container with the following command as the torrc configuration file won't exist yet.

    docker compose -f docker-compose_with_tor.yml run --name tor --rm tor \
        tor --allow-missing-torrc --SocksPort 0.0.0.0:9050

    docker compose -f docker-compose_with_tor.yml run -e TOR_PROXY_HOST=tor --rm swapclient \
            basicswap-prepare --usetorproxy --datadir=/coindata --withcoins=monero,particl


Start Basicswap with:

    docker compose -f docker-compose_with_tor.yml up

#### Enable tor on an existing datadir

    docker compose -f docker-compose_with_tor.yml run -e TOR_PROXY_HOST=tor --rm swapclient \
            basicswap-prepare --datadir=/coindata --enabletor

#### Disable tor on an existing datadir

    docker compose -f docker-compose_with_tor.yml run --rm swapclient \
            basicswap-prepare --datadir=/coindata --disabletor
