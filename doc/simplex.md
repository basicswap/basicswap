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
  `7.0.0`.  The minimum supported version is `7.0.0`; prepare refuses
  older versions.
- `SIMPLEX_WS_PORT`: Local WebSocket port, default `5225`.
- `SIMPLEX_SERVER_ADDRESS`: SMP server address.  Default:
  `smp://u2dS9sG8nMNURyZwqASV4yROM28Er0luVTx5X1CsMrU=@smp4.simplex.im`
- `SIMPLEX_SERVER_SOCKS_PROXY`: Optional `host:port` SOCKS5 proxy for
  `simplex-chat`.  If Tor is enabled in BasicSwap, the Tor SOCKS proxy
  is used automatically unless this override is set.

Prepare downloads the native build for your CPU: on macOS `aarch64`
(Apple Silicon) or `x86-64` (Intel), on Linux `x86_64` or `aarch64`.
On Linux, upstream only publishes Ubuntu builds: prepare reads
`/etc/os-release` and picks the Ubuntu 22.04 or 24.04 build to match
your release.  Debian-family distributions get the Ubuntu 24.04 build
with a warning.  On other distributions prepare fails; either install a
working `simplex-chat` binary manually and set `SIMPLEX_SKIP_VERIFY=1`,
or set `SIMPLEX_ALLOW_UNSUPPORTED_DISTRO=1` to try the Ubuntu 24.04
build anyway.

The Ubuntu builds are dynamically linked, so they need a glibc at least
as new as the Ubuntu release they were built on.  Debian 13 (trixie)
and newer run the 24.04 build; Debian 12 (bookworm) and older may not,
in which case the smoke test below fails at prepare time and a manual
install is required.

After download and verification, prepare runs the binary once
(`simplex-chat --version`) as a smoke test, so a binary that can't run
on your system fails at prepare time instead of node startup.

## Binary verification

The `simplex-chat` binary is verified the same way coin cores are: its
SHA-256 hash must be listed in the release `_sha256sums` manifest, and
the detached PGP signature over that manifest must verify against the
SimpleX Chat release signing key
`BBDF7BDAD1548B16836AF5B9D53BDFD153C366BA` (`build@simplex.chat`).  The
key is bundled locally or fetched from a keyserver on first prepare.

Upstream's signed manifest for 7.0.0 only lists the Ubuntu `x86_64`
builds.  For builds that are not in the manifest (Linux `aarch64`,
macOS, Windows) prepare checks the hash against the `SHA2-256(...)`
lines in the GitHub release notes instead and logs a warning, because
that hash is not covered by the PGP signature.

An existing binary at `bin/simplex/simplex-chat` is re-verified against
the manifest for `SIMPLEX_CHAT_VERSION` each time prepare adds the
network.  If it doesn't match (wrong version, manual replacement,
corruption) it is redownloaded.  After successful verification prepare
writes `bin/simplex/.verified` recording the version and hash.

At startup BasicSwap compares the binary's hash against `.verified` and
refuses to start the SimpleX network on a mismatch or if the configured
version is below 7.0.0 (other networks are unaffected).  Installs
without a `.verified` file start with a warning; re-run prepare to
create it.  The check result is logged at startup and recorded on the
running network config as `verify_status` (`ok`, `unverified`,
`missing`, `hash_mismatch`, `unsupported_version`) alongside
`client_version`.

Environment variables controlling verification:

- `SKIP_GPG_VALIDATION`: Skip the signature check (hash is still
  enforced), same as for coin cores.
- `SIMPLEX_SKIP_VERIFY`: Trust an existing binary without any checks.
  For manual installs or custom builds; no `.verified` file is written.
- `SIMPLEX_FORCE_DOWNLOAD`: Replace any existing binary with a fresh,
  verified download.
- `SIMPLEX_ALLOW_UNSUPPORTED_DISTRO`: Try the Ubuntu 24.04 build on an
  unsupported Linux distribution instead of failing.

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
            "client_version": "7.0.0",
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
