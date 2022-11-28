
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

    ssh -R 18081:localhost:18081 -N user@LOCAL_NODE_IP

And start monerod


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


## TODO

Features still required (of many):
 - Cached addresses must be regenerated after use.
 - Option to lookup data from public explorers / nodes.
 - Ability to swap coin-types without running nodes for all coin-types
 - More swap protocols
 - Manual method to set wallet seeds from particl mnemonic
    - prepare script tries to load seeds automatically, btc versions < 0.21 require a fully synced chain
