
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


### If installed through pip:

    cd basicswap
    git pull
    pip3 install .


## Update core versions

    basicswap-prepare -preparebinonly
