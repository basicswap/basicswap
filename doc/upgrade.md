
## Update basicswap version

### Docker

Update only the code:

    basicswap]$ git pull
    $ cd docker
    $ docker-compose build
    $ export COINDATA_PATH=[PATH_TO]
    $ docker-compose up

If the dependencies and db format have changed the container must be built with `--no-cache` and the db file moved to a backup.

    basicswap]$ git pull
    $ cd docker
    $ docker-compose build --no-cache
    $ export COINDATA_PATH=[PATH_TO]
    $ mv --backup=numbered $COINDATA_PATH/db.sqlite $COINDATA_PATH/db_bkp.sqlite
    $ docker-compose up

#### Update core versions

After updating the code and rebuilding the container run:

    basicswap/docker]$ export COINDATA_PATH=[PATH_TO]
    $ docker-compose run --rm swapclient \
        basicswap-prepare --datadir=/coindata --preparebinonly --withcoins=monero,bitcoin


Specify all required coins after `--withcoins=`, separated by commas.
If updating from versions below 0.21, you may need to add `wallet=wallet.dat` to the core config files.


## If installed through pip:

    $ export SWAP_DATADIR=/Users/$USER/coinswaps
    $ . $SWAP_DATADIR/venv/bin/activate && python -V
    $ cd $SWAP_DATADIR/basicswap
    $ git pull
    $ pip3 install .


#### Update core versions

    basicswap-prepare -preparebinonly --withcoins=monero,bitcoin
