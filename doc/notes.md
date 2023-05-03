
## Monero remote private node without ssh tunneling

Example connecting a basicswap instance running on a local node to a private
remote monero node running at 192.168.1.9 with rpc username and password:
test_user:test_pwd

Set the following in basicswap.json:

In chainclients.monero:
- connection_type - rpc
- manage_daemon - false
- manage_wallet_daemon - true
- rpchost - ip of remote monero node (192.168.1.9)
- rpcport - rpcport that monero is listening on remote node (18081)
- rpcuser - test_user
- rpcpassword - test_pwd


Edit monerod.conf on the remote node:

    data-dir=PATH_TO_MONERO_DATADIR
    restricted-rpc=1
    rpc-login=test_user:test_pwd
    rpc-bind-port=18081
    rpc-bind-ip=192.168.1.9
    prune-blockchain=1

Start the remote monerod binary with `--confirm-external-bind`

Remember to open port 18081 in the remote machine's firewall if necessary.

You can debug the connection using curl (from the local node)

    curl http://192.168.1.9:18081/json_rpc -u test_user:test_pwd --digest -d '{"jsonrpc":"2.0","id":"0","method":"get_info"}' -H 'Content-Type: application/json'


## Monero remote private node with ssh tunneling

Example connecting to a private remote monero node running at 192.168.1.9

Set the following in basicswap.json:

In chainclients.monero:
- connection_type - rpc
- manage_daemon - false
- manage_wallet_daemon - true
- rpchost - localhost
- rpcport - rpcport that monero is listening on remote node (18081)

On the remote machine open an ssh tunnel to port 18081:

    ssh -N -R 18081:localhost:18081 user@LOCAL_NODE_IP

And start monerod


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


Install coincurve

    git clone https://github.com/tecnovert/coincurve.git -b bsx_windows
    cd coincurve/
    pip3 install .


Install basicswap

    git clone https://github.com/tecnovert/basicswap.git
    cd basicswap
    pip3 install .


Test:

    basicswap-prepare.exe --help


## Run One Test

```
pytest -v -s tests/basicswap/test_xmr.py::Test::test_02_leader_recover_a_lock_tx
```


## Private Offers

To send a private offer:
 1. Recipient creates a new address to receive offers on.
 2. Recipient sends the pubkey for the newly created address to the offerer.
 3. Offerer imports the recipient's pubkey.
 4. Offerer sends a new offer to the recipients key instead of the public network.

Nodes will ignore offers sent on keys other than the network key or keys created for offer-receiving.



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
