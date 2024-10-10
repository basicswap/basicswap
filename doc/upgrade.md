
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
        basicswap-prepare --datadir=/coindata --preparebinonly --withcoins=monero,bitcoin


Specify all required coins after `--withcoins=`, separated by commas.
If updating from versions below 0.21, you may need to add `wallet=wallet.dat` to the core config files.


## If installed through pip:

    $ export SWAP_DATADIR=/Users/$USER/coinswaps
    $ . $SWAP_DATADIR/venv/bin/activate && python -V
    $ cd $SWAP_DATADIR/basicswap
    $ git pull
    $ pip3 install -r requirements.txt --require-hashes && pip3 install .


#### Update core versions

    basicswap-prepare --datadir=$SWAP_DATADIR -preparebinonly --withcoins=monero,bitcoin
