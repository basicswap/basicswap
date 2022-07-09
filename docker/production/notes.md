

Copy and edit .env config:

    $ cp example.env .env


Create docker-compose config:

    cat compose-fragments/0_start.yml > docker-compose.yml

    # Add the relevant coin fragments
    cat compose-fragments/1_bitcoin.yml >> docker-compose.yml
    cat compose-fragments/1_litecoin.yml >> docker-compose.yml
    cat compose-fragments/1_monero-daemon.yml >> docker-compose.yml
    cat compose-fragments/1_monero-wallet.yml >> docker-compose.yml

    cat compose-fragments/8_swapclient.yml >> docker-compose.yml

    # Copy for prepare script config
    cp docker-compose.yml docker-compose-prepare.yml
    cat compose-fragments/9_swapprepare.yml >> docker-compose-prepare.yml


