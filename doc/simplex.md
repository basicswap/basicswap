# SimpleX Message Network

BasicSwap can use [SimpleX Chat](https://simplex.chat) as a message
transport, alongside or instead of SMSG and Nostr.

All messages remain end-to-end encrypted with the SMSG payload format
regardless of the transport.  The SimpleX SMP server only ever sees
encrypted blobs.

## How it works

- Broadcast messages (offers) are sent to the shared **`#bsx`** group.
- Direct messages (bids and swap messages after a direct route is
  established) are sent over SimpleX direct chats.
- BasicSwap runs `simplex-chat` as a background process and talks to it
  over a local WebSocket API.

## Official group link

Join the official BasicSwap SimpleX group with:

```
https://smp4.simplex.im/g#6wTyP9neyb9ki_J8ntUqjL3q7CWWqPk3Z-o5bpuvfXg
```

Any node using this link in its SimpleX network settings connects to the
same `#bsx` broadcast room.

## Enabling

```
SIMPLEX_GROUP_LINK="https://smp4.simplex.im/g#6wTyP9neyb9ki_J8ntUqjL3q7CWWqPk3Z-o5bpuvfXg" \
basicswap-prepare --datadir=~/coinswaps --addnetwork=simplex
```

Environment variables read by prepare:

- `SIMPLEX_GROUP_LINK`: **Required** when adding SimpleX.  The official
  link is given above.
- `SIMPLEX_CHAT_VERSION`: `simplex-chat` release to download, default
  `6.3.5`.
- `SIMPLEX_WS_PORT`: Local WebSocket port, default `5225`.
- `SIMPLEX_SERVER_ADDRESS`: SMP server address.  Default:
  `smp://u2dS9sG8nMNURyZwqASV4yROM28Er0luVTx5X1CsMrU=@smp4.simplex.im`
- `SIMPLEX_SERVER_SOCKS_PROXY`: Optional `host:port` SOCKS5 proxy for
  `simplex-chat`.  If Tor is enabled in BasicSwap, the Tor SOCKS proxy
  is used automatically unless this override is set.

On macOS, prepare downloads the native build for your CPU (`aarch64` on
Apple Silicon, `x86-64` on Intel).

## Binary verification

The `simplex-chat` binary is verified the same way coin cores are: its
SHA-256 hash must be listed in the release `_sha256sums` manifest, and
the detached PGP signature over that manifest must verify against the
bundled SimpleX Chat release key
(`FB44AF81A45BDE327319797C85107E357D4A17FC`).

An existing binary at `bin/simplex/simplex-chat` is re-verified against
the manifest for `SIMPLEX_CHAT_VERSION` each time prepare adds the
network.  If it doesn't match (wrong version, manual replacement,
corruption) it is redownloaded.  After successful verification prepare
writes `bin/simplex/.verified` recording the version and hash.

At startup BasicSwap compares the binary's hash against `.verified` and
refuses to start the SimpleX network on a mismatch (other networks are
unaffected).  Installs without a `.verified` file start with a warning;
re-run prepare to create it.  The check result is exposed as
`verify_status` (`ok`, `unverified`, `missing`, `hash_mismatch`) along
with `client_version` in the `/json/networks` API endpoint.

Environment variables controlling verification:

- `SKIP_GPG_VALIDATION`: Skip the signature check (hash is still
  enforced), same as for coin cores.
- `SIMPLEX_SKIP_VERIFY`: Trust an existing binary without any checks.
  For manual installs or custom builds; no `.verified` file is written.
- `SIMPLEX_FORCE_DOWNLOAD`: Replace any existing binary with a fresh,
  verified download.

On macOS, `simplex-chat` may require Homebrew OpenSSL:

```
brew install openssl@3.0
```

This adds a section to `basicswap.json`:

```json
{
    "networks": [
        {
            "type": "simplex",
            "server_address": "smp://u2dS9sG8nMNURyZwqASV4yROM28Er0luVTx5X1CsMrU=@smp4.simplex.im",
            "client_path": "~/coinswaps/bin/simplex/simplex-chat",
            "ws_port": 5225,
            "group_link": "https://smp4.simplex.im/g#6wTyP9neyb9ki_J8ntUqjL3q7CWWqPk3Z-o5bpuvfXg",
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

To disable:

```
basicswap-prepare --datadir=~/coinswaps --disablenetwork=simplex
```

Restart BasicSwap after adding, removing, or reconfiguring SimpleX.

## Creating a new group

The official `#bsx` group must keep that local name — BasicSwap always
sends offers to `#bsx`.  To create a separate private group (for testing
or a closed network), run `simplex-chat` interactively:

```
/group bsx
/set voice #bsx off
/set files #bsx off
/set direct #bsx off
/set reactions #bsx off
/set reports #bsx off
/set disappear #bsx on week
/create link #bsx
```

Share the resulting link with every node that should join.

## Tests

```
export SIMPLEX_GROUP_LINK=<link>
export PYTHONPATH=$(pwd)
pytest -v tests/basicswap/extended/test_simplex.py
```

For multi-node integration tests set `TEST_MESSAGE_NETWORKS=simplex`
(or e.g. `smsg,simplex,nostr`) before running `test_persistent.py`
based suites.
