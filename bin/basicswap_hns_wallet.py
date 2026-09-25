#!/usr/bin/env python3
"""Create or restore the separate encrypted HNS wallet used by BasicSwap.

Secrets are read from a terminal, never command-line arguments or environment
variables. The one-shot Rust initializer performs the guarded database write.
"""

import argparse
import getpass
import sys

from basicswap.interface.hns.wallet_bridge import initialize_hns_wallet


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("create", "restore"))
    parser.add_argument("--bridge", required=True, help="Rust bridge executable")
    parser.add_argument("--database", required=True, help="new HNS wallet database")
    parser.add_argument(
        "--network", choices=("mainnet", "testnet", "regtest"), required=True
    )
    parser.add_argument("--restore-height", type=int, default=0)
    args = parser.parse_args()

    if not sys.stdin.isatty() or not sys.stdout.isatty():
        parser.error("an interactive terminal is required for wallet secrets")
    passphrase = getpass.getpass("HNS wallet passphrase: ")
    confirm = getpass.getpass("Confirm passphrase: ")
    if passphrase != confirm:
        parser.error("passphrases differ")
    phrase = None
    if args.operation == "restore":
        phrase = getpass.getpass("24-word HNS recovery phrase: ").strip()
    wallet_id, fingerprint, created_phrase = initialize_hns_wallet(
        args.bridge,
        args.database,
        args.network,
        args.restore_height,
        passphrase,
        phrase,
    )
    print(f"HNS wallet ID: {wallet_id.hex()}")
    print(f"HNS seed fingerprint: {fingerprint.hex()}")
    if created_phrase is not None:
        print("HNS recovery phrase (write it down before funding this wallet):")
        print(created_phrase)
    print("The seed fingerprint goes in BasicSwap's handshake chainclient settings.")


if __name__ == "__main__":
    main()
