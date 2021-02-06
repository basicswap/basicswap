
## Source code

    $ git clone https://github.com/tecnovert/basicswap.git


## Run Using Docker

Docker must be installed and started:

    $ sudo systemctl status docker | grep Active

Should return a line containing `active (running)`


Create the images:

    $ cd basicswap/docker
    $ docker-compose build

Prepare the datadir:
Set XMR_RPC_HOST and BASE_XMR_RPC_PORT to a public XMR node or exclude to run a local node.
Set xmrrestoreheight to the current xmr chain height.
Adjust `--withcoins` and `--withoutcoins` as desired, eg: `--withcoins=monero,bitcoin`.  By default only Particl is loaded.

    $ export COINDATA_PATH=/var/data/coinswaps
    $ docker run --rm -e XMR_RPC_HOST="node.xmr.to" -e BASE_XMR_RPC_PORT=18081 -t --name swap_prepare -v $COINDATA_PATH:/coindata i_swapclient \
    basicswap-prepare --datadir=/coindata --withcoins=monero --htmlhost="0.0.0.0" --xmrrestoreheight=2245107

Record the mnemonic from the output of the above command.


Start the container

    $ export COINDATA_PATH=/var/data/coinswaps
    $ docker-compose up

Open in browser: `http://localhost:12700`



### Add a coin

    $ docker-compose stop
    $ export COINDATA_PATH=/var/data/coinswaps
    $ docker run --rm -t --name swap_prepare -v $COINDATA_PATH:/coindata i_swapclient basicswap-prepare --datadir=/coindata --addcoin=bitcoin

You can copy an existing pruned datadir (excluding bitcoin.conf and any wallets) over to `$COINDATA_PATH/bitcoin`
Remove any existing wallets after copying over a pruned chain or the Bitcoin daemon won't start.


## Windows

Install Git:

    https://gitforwindows.org/

Right click in the directory you want the source code and select 'Git Bash Here':

    $ git clone https://github.com/tecnovert/basicswap.git

Setup Docker Desktop on the WSL 2 backend.
[docs.docker.com/docker-for-windows/wsl](https://docs.docker.com/docker-for-windows/wsl/)

Launch the docker commands through a WSL terminal.


Open cmd-prompt with windows key + R -> "cmd" -> Enter

    > wsl

Go to the directory containing the source code:

    cd /mnt/c/tmp/basicswap/docker/

The following will set COINDATA_PATH to a directory in your windows home dir.

    export COINDATA_PATH=$(wslpath "$(wslvar USERPROFILE)")/coinswaps
    echo $COINDATA_PATH
    /mnt/c/Users/USER/coinswaps


Continue from the [Run Using Docker](#run-using-docker) section.


## Run Without Docker:


### Ubuntu Setup:

    $ apt-get install -y wget python3-pip gnupg unzip protobuf-compiler automake libtool pkg-config

### OSX Setup:

Install Homebrew:

    https://brew.sh/

Command Line Tools:

    $ xcode-select --install

Dependencies:

    $ brew install wget unzip python git protobuf gnupg automake libtool pkg-config


### Basicswap:

    $ export SWAP_DATADIR=/Users/$USER/coinswaps
    $ mkdir -p "$SWAP_DATADIR/venv"
    $ python3 -m venv "$SWAP_DATADIR/venv"
    $ . $SWAP_DATADIR/venv/bin/activate && python -V
    $ cd $SWAP_DATADIR
    $ wget -O coincurve-anonswap.zip https://github.com/tecnovert/coincurve/archive/anonswap.zip
    $ unzip coincurve-anonswap.zip
    $ cd $SWAP_DATADIR/coincurve-anonswap
    $ pip3 install .


    $ cd $SWAP_DATADIR
    $ git clone https://github.com/tecnovert/basicswap.git
    $ cd $SWAP_DATADIR/basicswap
    $ protoc -I=basicswap --python_out=basicswap basicswap/messages.proto
    $ pip3 install .

Prepare the datadir:

    XMR_RPC_HOST="node.xmr.to" BASE_XMR_RPC_PORT=18081 basicswap-prepare --datadir=$SWAP_DATADIR --withcoins=monero --xmrrestoreheight=2245107

    OR using a local XMR daemon:
    basicswap-prepare --datadir=$SWAP_DATADIR --withcoins=monero --xmrrestoreheight=2245107

Record the mnemonic from the output of the above command.

Start the app

    $ basicswap-run --datadir=$SWAP_DATADIR

Open in browser: `http://localhost:12700`
It may take a few minutes to start as the coin daemons are started before the http interface.


Start after installed:

    $ export SWAP_DATADIR=/Users/$USER/coinswaps
    $ . $SWAP_DATADIR/venv/bin/activate && python -V
    $ basicswap-run --datadir=$SWAP_DATADIR
