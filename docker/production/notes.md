# Split container setup

This will setup Basicswap so that each coin runs in it's own container.


### Coin notes

    - Decred is only partially supported, the wallet will need to be initialised manually.


## Setup

Install dependencies:

    sudo apt install basez docker-compose


Copy and edit .env config:

    cp example.env .env


Set random RPC passwords, example.env leaves them empty and basicswap-prepare refuses an empty one:

    for KEY in $(grep -o '^.*_RPC_PWD' .env)
    do
        echo "Replacing: $KEY"
        NEW_PWD=$(cat /dev/random | base16 | head -c 48)
        sed -i "s/${KEY}=.*$/${KEY}=${NEW_PWD}/g" .env
    done


Set the latest Monero chain height, or the height your wallet must restore from:

    echo "DEFAULT_XMR_RESTORE_HEIGHT=$(curl https://localmonero.co/blocks/api/get_stats | jq .height)" >> .env


Create docker-compose config:

    # Using the helper script:
    ./scripts/build_yml_files.py -c bitcoin monero

    # Or manually:

    cat compose-fragments/0_start.yml > docker-compose.yml

    # Add the relevant coin fragments
    cat compose-fragments/1_bitcoin.yml >> docker-compose.yml
    cat compose-fragments/1_litecoin.yml >> docker-compose.yml
    cat compose-fragments/1_decred-wallet.yml >> docker-compose.yml
    cat compose-fragments/1_monero-wallet.yml >> docker-compose.yml
    cat compose-fragments/1_pivx.yml >> docker-compose.yml
    cat compose-fragments/1_dash.yml >> docker-compose.yml
    cat compose-fragments/1_firo.yml >> docker-compose.yml

    # Copy for prepare script config
    cp docker-compose.yml docker-compose-prepare.yml
    cat compose-fragments/9_swapprepare.yml >> docker-compose-prepare.yml

    # Add the Monero daemon if required (should not go in docker-compose-prepare.yml)
    cat compose-fragments/8_monero-daemon.yml >> docker-compose.yml

    # Add the swapclient
    cat compose-fragments/8_swapclient.yml >> docker-compose.yml


Create the docker network, with a specific subnet (for optional tor use):

    docker network create coinswap_network --subnet="172.16.238.0/24"


Build the swapclient container:

    docker-compose build swapclient


Build the monero container, if required:

    docker-compose build monero_daemon


Build the remaining coin containers:

    docker-compose build


Build the prepare-only containers:

    docker-compose -f docker-compose-prepare.yml build


Create config files:

    # Select relevant coins:
    export WITH_COINS=bitcoin,litecoin,monero

    docker-compose -f docker-compose-prepare.yml run --rm swapprepare \
        basicswap-prepare --nocores --usecontainers --withcoins=${WITH_COINS} --htmlhost="0.0.0.0" --particl_mnemonic=none


Start coin cores only:

    docker-compose -f docker-compose-prepare.yml up -d --scale swapprepare=0


Initialise wallets:

    docker-compose -f docker-compose-prepare.yml run --rm swapprepare \
        basicswap-prepare --initwalletsonly


Stop cores:

    docker-compose -f docker-compose-prepare.yml stop


Start BasicSwap:

    docker-compose up


## Update code

Rebuilding the bitcoin container installs the latest Bitcoin Core.  Migrate a
legacy Bitcoin wallet first, see "Migrate a legacy Bitcoin wallet".

    docker-compose stop

    pushd .
    cd ../../
    git pull
    popd

    docker-compose build monero_daemon
    docker-compose build decred_daemon
    docker-compose build

    docker-compose build --no-cache swapclient
    docker-compose up


## Migrate a legacy Bitcoin wallet

Bitcoin Core 30 and later can't load the legacy wallet of a Bitcoin install
prepared before Bitcoin Core 30.
Migrate the wallet while the old core still runs, before rebuilding the coin
containers:

    docker-compose stop

    pushd .
    cd ../../
    git pull
    popd

    docker-compose build --no-cache swapclient

    docker-compose -f docker-compose-prepare.yml up -d --scale swapprepare=0

    docker-compose -f docker-compose-prepare.yml run -e WALLET_ENCRYPTION_PWD=walletpass \
        --rm swapprepare \
        basicswap-prepare --migratewallets

    docker-compose -f docker-compose-prepare.yml stop

Then build the remaining containers and start BasicSwap as in "Update code".
Bitcoin Core first writes a backup of the legacy wallet,
`<wallet name>_<time>.legacy.bak`, in the bitcoin data directory.
If the bitcoin container was rebuilt first, BasicSwap stops at startup with a
message to run `basicswap-prepare --migratewallets`: run the steps above from
starting the cores.


## Add a coin


Stop all running containers

    docker-compose stop


Update docker-compose config:

Rebuild using the helper script (must list all enabled coins):

    ./scripts/build_yml_files.py -c bitcoin monero

Or

    cat compose-fragments/1_monero-wallet.yml >> docker-compose.yml
    cat compose-fragments/1_monero-wallet.yml >> docker-compose-prepare.yml

    # Add the Monero daemon if required (should not go in docker-compose-prepare.yml)
    cat compose-fragments/8_monero-daemon.yml >> docker-compose.yml


Prepare config files:

    docker-compose -f docker-compose-prepare.yml build swapprepare

    export ADD_COIN=monero
    docker-compose -f docker-compose-prepare.yml run --rm swapprepare \
        basicswap-prepare --nocores --usecontainers --addcoin=${ADD_COIN} --particl_mnemonic=none


Prepare wallet:

    docker-compose build monero_daemon
    docker-compose build

    docker-compose -f docker-compose-prepare.yml up -d --scale swapprepare=0

    docker-compose -f docker-compose-prepare.yml run -e WALLET_ENCRYPTION_PWD=walletpass \
        --rm swapprepare \
        basicswap-prepare --initwalletsonly --withoutcoin=particl --withcoin=${ADD_COIN}

    docker-compose -f docker-compose-prepare.yml stop

    docker-compose up


# Notes

Switch Basicswap repo or commit, the full commit id is required:
    docker-compose build swapclient --build-arg BASICSWAP_COMMIT=$(git ls-remote https://github.com/basicswap/basicswap refs/heads/dev | cut -f1)
    docker-compose build swapclient --build-arg BASICSWAP_REPO=https://github.com/<user>/basicswap.git --build-arg BASICSWAP_COMMIT=<commit>
