# BCH Notes

As at: v28.0.0

- BCH wallets must be fully synced before the `sethdseed` command will succeed.
  Fails with: "Cannot set a new HD seed while still in Initial Block Download"
  The workaround is to initialise the wallet after it has synced with the blockchain.
  Must be manually initiated from the BCH wallet page.


