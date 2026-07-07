# PIVX Notes

As at: v5.6.1

- PIVX wallets must be fully synced before the `sethdseed` command will succeed.
  Fails with: "Cannot set a new HD seed while still in Initial Block Download"
  The workaround is to initialise the wallet after it has synced with the blockchain.
  Must be manually initiated from the PIVX wallet page.


