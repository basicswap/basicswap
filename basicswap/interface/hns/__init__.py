"""Handshake integration components.

The node adapter is deliberately independent of BasicSwap's Bitcoin coin
interface. Handshake transactions and wallet operations need native handling.
"""

HNS_COIN = 1_000_000
HNS_MAX_MONEY = 2_040_000_000 * HNS_COIN
