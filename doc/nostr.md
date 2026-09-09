# Nostr Message Network

BasicSwap can use the [Nostr](https://nostr.com) protocol as a message
transport, alongside or instead of SMSG and SimpleX.

All messages remain end-to-end encrypted with the SMSG payload format
regardless of the transport.  Relays cannot read message contents, but
as with any nostr client they can see event metadata (sender pubkey,
timing and size).

## How it works

- Messages are published as Nostr events of kind `4859` to all configured
  relays, signed with BIP-340 keys that are not linked to any wallet key.
- Offers and other broadcasts are signed with the node's persistent
  `private_key`.  Each swap negotiates a direct message route with a
  fresh key pair generated for that route (exchanged in the CONNECT_REQ
  handshake and stored with the route), so bids and swap messages can't
  be linked to the node key or to other swaps by relays.  The ACK echoes
  the requester's route key and must be signed by the key it announces,
  so a stored ACK replayed by a relay can't activate a later route.
- Inbound events are gated before signature verification: relay
  messages over 72 KiB are dropped, each relay is limited to a burst of
  2000 events refilling at 20/s, and at most 5000 verified events are
  queued for processing.  Drop counters are shown per relay on the
  Settings -> Networks tab.
- The node key can be replaced at any time with "Regenerate Key" on the
  Settings -> Networks tab (restart required).  Existing routes keep
  their own keys, so in-progress swaps are not affected.
- Every BSX event is tagged `["t", "bsx"]` (offers, handshake, and swap
  messages).  Payloads stay encrypted to the recipient's smsg address.
- Events carry a NIP-40 `expiration` tag matching the SMSG TTL, so relays
  can prune them automatically.
- Optionally, outgoing events can commit NIP-13 proof of work
  (`pow_target` setting, 0-12 bits) for relays that require it.
  Mining runs on the send path, so higher targets delay outgoing
  messages.  Leave at `0` unless a relay demands it.

## Enabling

From Settings → Networks, use **Add Nostr**, or:

```
basicswap-prepare --datadir=~/coinswaps --addnetwork=nostr
```

Environment variables read by prepare:

- `NOSTR_RELAYS`: Comma separated relay urls.
  Default: `wss://relay.damus.io,wss://nos.lol,wss://relay.primal.net`
- `NOSTR_POW_TARGET`: NIP-13 difficulty bits for outgoing events,
  default `0`, max `12`.
- `NOSTR_SOCKS_PROXY`: Optional `host:port` SOCKS5 proxy override.

This adds a section to `basicswap.json`:

```json
{
    "networks": [
        {
            "type": "nostr",
            "relays": ["wss://relay.damus.io", "wss://nos.lol"],
            "private_key": "<32 byte hex key>",
            "pow_target": 0,
            "enabled": true
        }
    ]
}
```

Multiple networks can be enabled at the same time.  When more than one
network is active, set `"smsg_payload_version": 2` so messages can be
deduplicated across networks.

Networks can also be enabled/disabled and configured from the
Settings -> Networks tab in the UI, and inspected through the
`/json/networks` API endpoint.

Nodes running multiple networks can optionally relay messages between
them for other nodes by setting the top-level `"bridge_networks": true`
setting (also available as "Network Bridging" on the Settings -> Networks
tab).  This is not required to send and receive on multiple networks
yourself, only to help nodes on disjoint networks reach each other.

To disable:

```
basicswap-prepare --datadir=~/coinswaps --disablenetwork=nostr
```

If Tor is enabled for BasicSwap, relay connections are routed through the
Tor SOCKS proxy unless `socks_proxy_override` is set for the network.

Use `wss://` relays.  Plain `ws://` relays without Tor expose your Nostr
pubkey and message timing on the wire (payloads stay encrypted); a
warning is logged at startup and shown in the settings tab.

## Tests

Unit and integration tests (no external infrastructure):

```
export PYTHONPATH=$(pwd)
pytest -v tests/basicswap/test_nostr.py
```

The tests run against an in-process mini relay
(`tests/basicswap/util/nostr_relay.py`).

### Regtest swap tests

Full BTC↔XMR regtest swaps over Nostr (3 nodes, in-process relay):

```
export PYTHONPATH=$(pwd)
pytest -v -s tests/basicswap/extended/test_nostr.py
```

Nostr ↔ SMSG bridge swaps:

```
pytest -v -s tests/basicswap/extended/test_multinet_nostr.py
```

All three networks (SMSG + SimpleX + Nostr) — requires SimpleX SMP server
and `simplex-chat` binary (see `tests/basicswap/extended/test_simplex.py`):

```
pytest -v -s tests/basicswap/extended/test_multinet_all.py
```

Or use the regtest runner (copies coin binaries to `/tmp/test_basicswap_bin`):

```
scripts/run_nostr_regtest_tests.sh
RUN_MULTINET_ALL=1 scripts/run_nostr_regtest_tests.sh   # include SimpleX tests
```

For multi-node integration tests in `test_persistent.py` based suites, set
`TEST_MESSAGE_NETWORKS=nostr` (or e.g. `smsg,nostr`) and optionally
`TEST_MESSAGE_NETWORKS_BRIDGE=smsg` to attach bridged networks.  Point
`NOSTR_TEST_RELAYS` at a reachable relay (defaults to `ws://127.0.0.1:8765`).
