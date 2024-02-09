
## Source code

    git clone https://github.com/tecnovert/basicswap.git


## Run Using Docker


Install dependencies:

    apt-get install curl jq git


Docker must be installed and started:

    docker -v

Should return a line containing `Docker version`...


To install docker engine on your platform see:

    https://docs.docker.com/engine/install/#server


It's recommended to setup docker to work without sudo.<br>
Without this step you will need to preface each `docker-compose` command with `sudo`:

    https://docs.docker.com/engine/install/linux-postinstall/


#### (Optional) Set custom coin data path:

Coin-related files, such as blockchain and wallet files, are stored in `/var/data/coinswaps` by default. To use a different location, simply modify the target path in your `.env` file found within the `/docker` sub-folder.

    cd basicswap/docker
    nano .env

#### Create the images:

    cd basicswap/docker
    docker-compose build

Depending on your environment, the `docker-compose` command may not work. If that's the case, type `docker compose` instead, without the dash.

#### Prepare the datadir:

Set xmrrestoreheight to the current xmr chain height.

    CURRENT_XMR_HEIGHT=$(curl https://localmonero.co/blocks/api/get_stats | jq .height)

Adjust `--withcoins` and `--withoutcoins` as desired, eg: `--withcoins=monero,bitcoin`.  By default only Particl is loaded.

##### FastSync

Append `--usebtcfastsync` to the below command to optionally initialise the Bitcoin datadir with a chain snapshot from btcpayserver FastSync.<br>
[FastSync README.md](https://github.com/btcpayserver/btcpayserver-docker/blob/master/contrib/FastSync/README.md)


Setup with a local Monero daemon (recommended):

    docker run --rm -t --name swap_prepare -v $COINDATA_PATH:/coindata i_swapclient basicswap-prepare --datadir=/coindata --withcoins=monero --htmlhost="0.0.0.0" --wshost="0.0.0.0" --xmrrestoreheight=$CURRENT_XMR_HEIGHT


To instead use Monero public nodes and not run a local Monero daemon<br>(it can be difficult to find reliable public nodes):

    Set XMR_RPC_HOST and BASE_XMR_RPC_PORT to a public XMR node.
    docker run --rm -e XMR_RPC_HOST="node.xmr.to" -e BASE_XMR_RPC_PORT=18081 -t --name swap_prepare -v $COINDATA_PATH:/coindata i_swapclient basicswap-prepare --datadir=/coindata --withcoins=monero --htmlhost="0.0.0.0" --wshost="0.0.0.0" --xmrrestoreheight=$CURRENT_XMR_HEIGHT


**Record the mnemonic from the output of the above command.**
**Mnemonics should be stored encrypted and/or air-gapped.**
And the output of `echo $CURRENT_XMR_HEIGHT` for use if you need to later restore your wallet.

#### Set the timezone (optional):

Edit the `.env` file in the docker directory, set TZ to your local timezone.
Valid options can be listed with: `timedatectl list-timezones`


#### Start the container:

    docker-compose up

Open in browser: `http://localhost:12700`



### Add a coin

    docker-compose stop
    docker run --rm -t --name swap_prepare -v $COINDATA_PATH:/coindata i_swapclient basicswap-prepare --datadir=/coindata --addcoin=bitcoin --usebtcfastsync

You can copy an existing pruned datadir (excluding bitcoin.conf and any wallets) over to `$COINDATA_PATH/bitcoin`
Remove any existing wallets after copying over a pruned chain or the Bitcoin daemon won't start.


With Encryption

    docker run -e WALLET_ENCRYPTION_PWD=passwordhere --rm -t --name swap_prepare -v $COINDATA_PATH:/coindata i_swapclient basicswap-prepare --datadir=/coindata --addcoin=bitcoin --usebtcfastsync


## Windows

#### Setup WSL 2 and Docker Desktop
[docs.docker.com/docker-for-windows/wsl](https://docs.docker.com/docker-for-windows/wsl/)


Open a wsl terminal
Windows key + R -> "wsl" -> Enter


Install Git:

    sudo apt update
    sudo apt install git


Download the BasicSwap code:

    git clone https://github.com/tecnovert/basicswap.git
    cd basicswap/docker/


It's significantly faster to set COINDATA_PATH in the linux filesystem.
You can access it from the windows side at: `\\wsl$\Ubuntu`

Continue from the [Run Using Docker](#run-using-docker) section.


## Run Without Docker:


### Ubuntu Setup:

    apt-get install -y wget git python3-venv python3-pip gnupg unzip protobuf-compiler automake libtool pkg-config curl jq

### OSX Setup:

Install Homebrew (See https://brew.sh/):

    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

Dependencies:

    brew install wget unzip python git protobuf gnupg automake libtool pkg-config curl jq

Close the terminal and open a new one to update the python symlinks.


### Basicswap:

    export SWAP_DATADIR=/Users/$USER/coinswaps
    mkdir -p "$SWAP_DATADIR/venv"
    python3 -m venv "$SWAP_DATADIR/venv"
    . $SWAP_DATADIR/venv/bin/activate && python -V
    cd $SWAP_DATADIR
    wget -O coincurve-anonswap.zip https://github.com/tecnovert/coincurve/archive/refs/tags/anonswap_v0.2.zip
    unzip -d coincurve-anonswap coincurve-anonswap.zip
    mv ./coincurve-anonswap/*/{.,}* ./coincurve-anonswap || true
    cd $SWAP_DATADIR/coincurve-anonswap
    pip3 install .


    cd $SWAP_DATADIR
    git clone https://github.com/tecnovert/basicswap.git
    cd $SWAP_DATADIR/basicswap


If installed on OSX, you may need to install additional root ssl certificates for the ssl module.
From https://pypi.org/project/certifi/

    sudo python3 bin/install_certifi.py


Continue installing Basicswap

    protoc -I=basicswap --python_out=basicswap basicswap/messages.proto
    pip3 install .


Prepare the datadir:

    CURRENT_XMR_HEIGHT=$(curl https://localmonero.co/blocks/api/get_stats | jq .height)

    basicswap-prepare --datadir=$SWAP_DATADIR --withcoins=monero --xmrrestoreheight=$CURRENT_XMR_HEIGHT

    OR using a remote/public XMR daemon (not recommended):
    XMR_RPC_HOST="node.xmr.to" BASE_XMR_RPC_PORT=18081 basicswap-prepare --datadir=$SWAP_DATADIR --withcoins=monero --xmrrestoreheight=$CURRENT_XMR_HEIGHT


Record the mnemonic from the output of the above command.

Start Basicswap:

    basicswap-run --datadir=$SWAP_DATADIR


Open in browser: `http://localhost:12700`
It may take a few minutes to start as the coin daemons are started before the http interface.


Add a coin (Stop basicswap first):

    export SWAP_DATADIR=/Users/$USER/coinswaps
    basicswap-prepare --usebtcfastsync --datadir=/$SWAP_DATADIR --addcoin=bitcoin


Start after installed:

    export SWAP_DATADIR=/Users/$USER/coinswaps
    . $SWAP_DATADIR/venv/bin/activate && python -V
    basicswap-run --datadir=$SWAP_DATADIR
