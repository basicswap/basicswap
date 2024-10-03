## DASH Notes

### Importing wallets created with DASH version <21


From version 21 DASH core can use the sethdseed rpc command.
The old method to import a seed used the DASH specific upgradetohd rpc command.


To import a wallet created on DASH v20 use basicswap-prepare with the --dashv20compatible flag.

Example:

    basicswap-prepare --withcoins=dash --particl_mnemonic="..." --dashv20compatible
