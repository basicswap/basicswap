# Nostr Message Network

BasicSwap can use the [Nostr](https://nostr.com) protocol as a message
transport, alongside or instead of SMSG and SimpleX.

All messages remain end-to-end encrypted with the SMSG payload format
regardless of the transport.  Relays cannot read message contents, but
as with any nostr client they can see event metadata (sender pubkey,
recipient tag, timing and size).  Events are signed with a persistent
key, generate a new `private_key` to unlink from earlier activity.

## How it works

- Messages are published as Nostr events of kind `4859` to all configured
  relays, signed with a dedicated BIP-340 key (not linked to any wallet key).
- Broadcast messages (offers) are tagged `["t", "bsx"]`.  All BSX nodes
  subscribe to this tag.
- Direct messages (bids and swap messages after a direct route is
  established) are tagged `["p", <recipient pubkey>]` and also
  `["t", "bsx"]`.  Public relays often accept `#p`-only events without
  delivering them, so the broadcast tag is required for two-node swaps.
- Events carry a NIP-40 `expiration` tag matching the SMSG TTL, so relays
  can prune them automatically.
- Optionally, outgoing events can commit NIP-13 proof of work
  (`pow_target` setting, 0-12 bits) for relays that require it.
  Mining runs on the send path, so higher targets delay outgoing
  messages.  Leave at `0` unless a relay demands it.

## Enabling

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

## Tests

```
export PYTHONPATH=$(pwd)
pytest -v tests/basicswap/test_nostr.py
```

The tests run against an in-process mini relay
(`tests/basicswap/util/nostr_relay.py`) and require no external
infrastructure.  For multi-node integration tests set
`TEST_MESSAGE_NETWORKS=nostr` (or e.g. `smsg,nostr`) and point
`NOSTR_TEST_RELAYS` at a reachable relay before running
`test_persistent.py` based suites.
