# SimpleX Message Network

BasicSwap can use [SimpleX Chat](https://simplex.chat) as a message
transport, alongside or instead of SMSG.

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
same `#bsx` broadcast room.  To run a private network instead, create
your own group in `simplex-chat` (`/g bsx`, then `/create link #bsx`)
and share the resulting link with the other nodes.

## Enabling

```
basicswap-prepare --datadir=~/coinswaps --addnetwork=simplex
```

Environment variables read by prepare:

- `SIMPLEX_GROUP_LINK`: Group to join.  Defaults to the official link
  given above; set it to join a private network instead.
- `SIMPLEX_CHAT_VERSION`: `simplex-chat` release to download, default
  `7.0.0`.
- `SIMPLEX_WS_PORT`: Local WebSocket port, default `5225`.
- `SIMPLEX_SERVER_ADDRESS`: SMP server address.  Default:
  `smp://u2dS9sG8nMNURyZwqASV4yROM28Er0luVTx5X1CsMrU=@smp4.simplex.im`

When Tor is enabled in BasicSwap, `simplex-chat` connects through the
same Tor SOCKS proxy as the rest of BasicSwap.

Prepare downloads the native build for your CPU: on macOS `aarch64`
(Apple Silicon) or `x86-64` (Intel), on Linux `x86_64` or `aarch64`.
On Linux, upstream only publishes Ubuntu builds.  Prepare always uses
the Ubuntu 22.04 build: it is dynamically linked against glibc 2.35, so
it also runs on newer glibc distributions (Ubuntu 24.04, Debian 12,
Arch, ...).

## Binary verification

The `simplex-chat` binary is verified the same way coin cores are: its
SHA-256 hash must be listed in the release `_sha256sums` manifest, and
the detached PGP signature over that manifest must verify against the
SimpleX Chat release signing key
`BBDF7BDAD1548B16836AF5B9D53BDFD153C366BA` (`build@simplex.chat`).  The
key is bundled locally or fetched from a keyserver on first prepare.

Upstream's signed manifest for 7.0.0 only lists the Ubuntu `x86_64`
builds.  The other builds (Linux `aarch64`, macOS, Windows) are not in
the signed manifest and fail verification.

The release is kept in `bin/simplex/<version>/` and verified each time
prepare adds the network, then copied to `bin/simplex/simplex-chat`.
`SKIP_GPG_VALIDATION` and `--redownloadreleases` behave as they do for
coin cores.

For a build that is not in the signed manifest, or one built or
installed another way, place the binary at `bin/simplex/simplex-chat`
and add the network with `--nocores`, which skips the download and
verification:

```
basicswap-prepare --datadir=~/coinswaps --addnetwork=simplex --nocores
```

On macOS, `simplex-chat` may require Homebrew OpenSSL:

```
brew install openssl@3.0
```

This adds a section to `basicswap.json`, other networks stay enabled.
To use SimpleX instead of SMSG, also run `--disablenetwork=smsg`.

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

To disable:

```
basicswap-prepare --datadir=~/coinswaps --disablenetwork=simplex
```

Restart BasicSwap after adding, removing, or reconfiguring SimpleX.

## Changing the group

BasicSwap records the link it joined with as `joined_group_link` next
to `group_link` in the network settings.  When `group_link` is changed
(in `basicswap.json`, through the Settings page, or by re-running
`--addnetwork=simplex` with a new `SIMPLEX_GROUP_LINK`) and BasicSwap is
restarted, it leaves and deletes the groups in its `simplex-chat`
database and joins the new link, then updates `joined_group_link`.
Direct contacts used for bid messages are kept.

If this node owns the current group (it created the group and link
itself) the switch is refused and SimpleX does not start; leave or
delete the group in `simplex-chat` first, or keep the link.  Nodes
upgraded from a version without `joined_group_link` record their
configured `group_link` as joined at the next start, so change the link
only after that first restart.

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

For multi-node integration tests point `SIMPLEX_CLIENT_PATH` at a
verified `simplex-chat` binary and set `SIMPLEX_GROUP_LINK` (plus any
other `SIMPLEX_*` overrides) before running `test_persistent.py` based
suites.
