
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
Adjust `--withcoins` and `--withoutcoins` as desired, eg: `--withcoins=monero,bitcoin`.  By default Particl and Litecoin are loaded.

    $ export COINDATA_PATH=/var/data/coinswaps
    $ docker run -e XMR_RPC_HOST="node.xmr.to" -e BASE_XMR_RPC_PORT=18081 -t --name swap_prepare -v $COINDATA_PATH:/coindata i_swapclient \
    basicswap-prepare --datadir=/coindata --withcoins=monero --withoutcoins=litecoin --htmlhost="0.0.0.0" --xmrrestoreheight=2245107

Record the mnemonic from the output of the above command.

Remove swap_prepare container (and logs):

    $ docker rm swap_prepare


Start the container

    $ export COINDATA_PATH=/var/data/coinswaps
    $ docker-compose up

Open in browser: `http://localhost:12700`

### Add a coin

    $ docker-compose stop
    $ export COINDATA_PATH=/var/data/coinswaps
    $ docker run -t --name swap_prepare -v $COINDATA_PATH:/coindata i_swapclient basicswap-prepare --datadir=/coindata --addcoin=bitcoin

You can copy an existing pruned datadir (excluding bitcoin.conf and any wallets) over to `$COINDATA_PATH/bitcoin`
Remove any existing wallets after copying over a pruned chain or the Bitcoin daemon won't start.


## Run Without Docker:

    $ apt-get install -y wget python3-pip gnupg unzip protobuf-compiler automake libtool pkg-config

    $ export SWAP_DATADIR=/var/data/coinswaps
    $ mkdirs -p "$SWAP_DATADIR/venv"
    $ python3 -m venv "$SWAP_DATADIR/venv"
    $ . $SWAP_DATADIR/venv/bin/activate && python -V
    $ wget -O coincurve-anonswap.zip https://github.com/tecnovert/coincurve/archive/anonswap.zip
    $ unzip coincurve-anonswap.zip
    $ cd coincurve-anonswap
    $ python3 setup.py install --force


    $ cd $SWAP_DATADIR
    $ git clone https://github.com/tecnovert/basicswap.git
    $ cd basicswap
    $ protoc -I=basicswap --python_out=basicswap basicswap/messages.proto
    $ pip3 install .

Prepare the datadir:

    XMR_RPC_HOST="node.xmr.to" BASE_XMR_RPC_PORT=18081 basicswap-prepare --datadir=$SWAP_DATADIR --withcoins=monero --withoutcoins=litecoin --xmrrestoreheight=2245107

Record the mnemonic from the output of the above command.

Start the app

    $ basicswap-run --datadir=$SWAP_DATADIR

Open in browser: `http://localhost:12700`


Old notes
=============

## Run Without Installing

    $ cd basicswap
    $ pip install sqlalchemy protobuf pyzmq
    $ protoc -I=basicswap --python_out=basicswap basicswap/messages.proto
    $ export PYTHONPATH=$(pwd)
    $ python bin/basicswap-prepare.py
    $ python bin/basicswap-run.py


## OSX

Install Homebrew:

    https://brew.sh/

Command Line Tools:

    $ xcode-select --install

Dependencies:

    $ brew install python git protobuf gnupg

Python certificates:

    $ /Applications/Python\ 3.7/Install\ Certificates.command

Basicswap

    $ git clone https://github.com/tecnovert/basicswap.git
    $ cd basicswap
    $ protoc -I=basicswap --python_out=basicswap basicswap/messages.proto
    $ pip3 install .
    $ basicswap-prepare
    $ basicswap-run


# Windows

Install git and python3:

    https://gitforwindows.org/
    https://www.python.org/downloads/windows/
        Remember to select the 'Add Python to environment variables' option.

Right click in the directory you want to install into and select 'Git Bash Here':

    $ git clone https://github.com/tecnovert/basicswap.git
    $ cd basicswap
    $ pip3 install .
    $ basicswap-prepare
    $ basicswap-run

Open url in browser:
http://localhost:12700

Shutdown by pressing ctrl + c in the Git Bash console window.
