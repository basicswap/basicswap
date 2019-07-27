
## Prerequisites

    $ sudo apt-get install git python3-pip protobuf-compiler
    $ git clone https://github.com/tecnovert/basicswap.git


## Run Using Docker

Docker must be installed and started:
    $ sudo systemctl status docker | grep Active

Should return a line containing:
`active (running)`

    $ cd basicswap/docker
    $ docker-compose build
    $ docker-compose up

You may need to run docker-compose with sudo, unless you've setup docker
to be able to run from user accounts.


By default the data dir will be basicswap/docker/coindata

To run with a different data directory run:

    $ export COINDATA_PATH=/tmp/part_swap_test/coindata

And copy the initial config there:

    $ cp -r docker/coindata /tmp/part_swap_test/coindata

Before running docker-compose build


## Install as Python Module with PIP

    $ cd basicswap
    $ protoc -I=basicswap --python_out=basicswap basicswap/messages.proto
    $ pip3 install .
    $ basicswap-prepare
    $ basicswap-run


By default the data dir will be `~/.basicswap`
To run in a different directory and on testnet:
```
    $ basicswap-prepare -datadir=~/part_swap_test -testnet
    $ basicswap-run -datadir=~/part_swap_test -testnet
```


## Run Without Installing

    $ cd basicswap
    $ pip install sqlalchemy protobuf pyzmq
    $ protoc -I=basicswap --python_out=basicswap basicswap/messages.proto
    $ export PYTHONPATH=$(pwd)
    $ python bin/basicswap-prepare.py
    $ python bin/basicswap-run.py


## OSX

    $ brew install python git protobuf
    $ git clone https://github.com/tecnovert/basicswap.git
    $ cd basicswap
    $ protoc -I=basicswap --python_out=basicswap basicswap/messages.proto
    $ pip3 install .
    $ basicswap-prepare
    $ basicswap-run
