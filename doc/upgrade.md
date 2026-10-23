
## Update basicswap version

### Docker

First ensure that docker is running.
If `docker ps` returns an error try:

    sudo systemctl start docker

Update only the code (prepend sudo to each docker command if necessary):

    basicswap]$ git pull
    cd docker
    docker-compose build
    docker-compose up

If the dependencies have changed the container must be built with `--no-cache`:

    basicswap]$ git pull
    cd docker
    docker-compose build --no-cache
    docker-compose up


#### Update core versions

After updating the code and rebuilding the container run:


    basicswap/docker]$ docker-compose run --rm swapclient \
        basicswap-prepare --datadir=/coindata --upgradecores


If updating from versions below 0.21, you may need to add `wallet=wallet.dat` to the core config files.


## If installed through pip:

    $ export SWAP_DATADIR=/Users/$USER/coinswaps
    $ . $SWAP_DATADIR/venv/bin/activate && python -V
    $ cd $SWAP_DATADIR/basicswap
    $ git pull
    $ pip3 install -r requirements.txt --require-hashes && pip3 install .


#### Update core versions

    basicswap-prepare --datadir=$SWAP_DATADIR --upgradecores


## Legacy Bitcoin wallets

Bitcoin Core 30 and later can't load the legacy wallet of a Bitcoin install
prepared before Bitcoin Core 30, so `--upgradecores` upgrades those installs
to the last 29.x release instead.
To upgrade to the latest Bitcoin Core and migrate the wallet to a descriptor
wallet, add `--uselatest=bitcoin`:

    basicswap-prepare --datadir=$SWAP_DATADIR --upgradecores --uselatest=bitcoin

Or with docker:

    basicswap/docker]$ docker-compose run --rm swapclient \
        basicswap-prepare --datadir=/coindata --upgradecores --uselatest=bitcoin

The wallet is migrated on the installed core, before the new one is
installed, and Bitcoin Core first writes a backup of the legacy wallet,
`<wallet name>_<time>.legacy.bak`.
If the Particl wallet is encrypted the password is read from
`WALLET_ENCRYPTION_PWD`, or asked for on the terminal.
A Bitcoin wallet not derived from the Particl wallet's default account is
refused unless `--noseedcheck` is added.
`basicswap-prepare --migratewallets` runs only the migration, without the
seed check, to retry it.

For the production docker setup, where each core runs in its own container,
see "Migrate a legacy Bitcoin wallet" in
[docker/production/notes.md](../docker/production/notes.md).
