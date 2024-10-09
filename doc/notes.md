
## Monero remote private node without ssh tunneling

Example connecting a basicswap instance running on a local node to a private
remote monero node running at 192.168.1.9 with rpc username and password:
test_user:test_pwd

Set the following in basicswap.json:

In chainclients.monero:
- connection_type - rpc
- manage_daemon - false
- manage_wallet_daemon - true
- rpchost - ip of remote monero node (example: 192.168.1.9)
- rpcport - rpcport that monero is listening on remote node (18089)
- rpcuser - test_user
- rpcpassword - test_pwd


Edit monerod.conf on the remote node:

    rpc-login=test_user:test_pwd
    rpc-restricted-bind-port=18089
    rpc-restricted-bind-ip=0.0.0.0

Remember to open port 18089 in the remote machine's firewall if necessary.

You can debug the connection using curl (from the local node)

    curl http://node.ip.addr.here:18089/json_rpc -u test_user:test_pwd --digest -d '{"jsonrpc":"2.0","id":"0","method":"get_info"}' -H 'Content-Type: application/json'


## Monero remote private node with ssh tunneling

Example connecting to a private remote monero node over ssh:

Set the following in basicswap.json:

In chainclients.monero:
- connection_type - rpc
- manage_daemon - false
- manage_wallet_daemon - true
- rpchost - localhost
- rpcport - rpcport that monero is listening on remote node (18089)

Edit monerod.conf on the remote node:

    rpc-restricted-bind-port=18089

On the remote machine open an ssh tunnel to BSX:

    ssh -N -R 18089:localhost:18089 user@LOCAL_BSX_IP

Or, on the BSX host machine create a tunnel to the node:

    ssh -N -L 18089:localhost:18089 user@REMOTE_NODE_IP



## SSH Tunnel to Remote BasicSwap Node

While basicswap can be configured to host on an external interface:

If not using docker by changing 'htmlhost' and 'wshost' in basicswap.json
For docker change 'HTML_PORT' and 'WS_PORT' in the .env file in the same dir as docker-compose.yml

A better solution is to use ssh to forward the required ports from the machine running bascswap to the client.

    ssh -N -L 5555:localhost:12700 -L 11700:localhost:11700 BASICSWAP_HOST

Run from the client machine (not running basicswap) will forward the basicswap ui on port 12700 to port 5555
on the local machine and also the websocket port at 11700.
The ui port on the client machine can be anything but the websocket port must match 'wsport' in basicswap.json.


## Installing on Windows Natively

This is not a supported installation method!

Install prerequisites:
- https://gitforwindows.org/
- https://www.python.org/downloads/windows/


In the start menu find Git / Git Bash
Right click Git Bash -> More -> run as administrator


Create and activate a venv

    python -m venv c:\bsx_venv
    c:/bsx_venv/scripts/activate

Install basicswap

    git clone https://github.com/basicswap/basicswap.git
    cd basicswap
    pip3 install .


Test:

    basicswap-prepare.exe --help


## Run One Test

    pytest -v -s tests/basicswap/test_xmr.py::Test::test_02_leader_recover_a_lock_tx


## Private Offers

To send a private offer:
 1. Recipient creates a new address to receive offers on.
 2. Recipient sends the pubkey for the newly created address to the offerer.
 3. Offerer imports the recipient's pubkey.
 4. Offerer sends a new offer to the recipients key instead of the public network.

Nodes will ignore offers sent on keys other than the network key or keys created for offer-receiving.


## Coin reindexing

    export COINDATA_PATH=/var/data/coinswaps
    cd $COINDATA_PATH/bin/firo
    ./firod -reindex -datadir=$COINDATA_PATH/firo -nodebuglogfile -printtoconsole > /tmp/firo.log

Observe progress with

    tail -f /tmp/firo.log



## FAQ

### How can I double check my backup words / mnemonic phrase

There's no way to get the words used during the install process as
BSX doesn't store the mnemonic words.

If you have the mnemonic words and want to double check if they're correct you can decode the mnemonic and compare the key ids.

For example, if the words are:
"abandon baby cabbage dad eager fabric gadget habit ice kangaroo lab absorb"

In the rpc console:
http://127.0.0.1:12700/rpc

Select Particl and input `extkey` to get the current root_key_id

    extkey
    [
      {
        "type": "Loose",
        "label": "Master Key - bip44 derived.",
        "path": "m/44h/1h",
        "key_type": "Master",
        "current_master": "true",
        "root_key_id": "xDALBKsFzxtkDPm6yoatAgNfRwavZTEheC",
        "id": "xHRmcdjD2kssaM5ZY8Cyzj8XWJsBweydyP",
        ...
      },
      {
        "type": "Account",
        "label": "Default Account",
        "root_key_id": "xHRmcdjD2kssaM5ZY8Cyzj8XWJsBweydyP",
        "path": "m/0h",
        ...
      }
    ]

Get the extkeys the mnemonic decodes to with `mnemonic decode` (Never share the keys!)

    mnemonic decode "" "abandon baby cabbage dad eager fabric gadget habit ice kangaroo lab absorb"
      "master": "tprv8ZgxMBicQKsPeK5mCpvMsd1cwyT1JZsrBN82XkoYuZY1EVK7EwDaiL9sDfqUU5SntTfbRfnRedFWjg5xkDG5i3iwd3yP7neX5F2dtdCojk4",
      "derived": "xparFhz8oNupLZBVCLZCDpXnaLf2H9uWxvZEmPQm2Hdsv5YZympmJZYXjbuvE1rRK4o8TMsbbpCWrbQbNvt7CZCeDULrgeQMi536vTuxvuXpWqN",

The master key should match the root_key_id of the "Master Key - bip44 derived." loose key from `extkey`

    extkey tprv8ZgxMBicQKsPeK5mCpvMsd1cwyT1JZsrBN82XkoYuZY1EVK7EwDaiL9sDfqUU5SntTfbRfnRedFWjg5xkDG5i3iwd3yP7neX5F2dtdCojk4
    "id": "xDALBKsFzxtkDPm6yoatAgNfRwavZTEheC",

And/or the derived key should match the account key root_key_id from `extkey`:

    extkey xparFhz8oNupLZBVCLZCDpXnaLf2H9uWxvZEmPQm2Hdsv5YZympmJZYXjbuvE1rRK4o8TMsbbpCWrbQbNvt7CZCeDULrgeQMi536vTuxvuXpWqN
    "id": "xHRmcdjD2kssaM5ZY8Cyzj8XWJsBweydyP",





## TODO

Features still required (of many):
 - Cached addresses must be regenerated after use.
 - Option to lookup data from public explorers / nodes.
 - Ability to swap coin-types without running nodes for all coin-types
 - More swap protocols
 - Manual method to set wallet seeds from particl mnemonic
    - prepare script tries to load seeds automatically, btc versions < 0.21 require a fully synced chain
