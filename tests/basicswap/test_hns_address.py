"""Address vector pinned by hns-wallet-rs native wallet tests."""

import unittest

from basicswap.interface.hns.address import (
    decode_v0_address,
    encode_v0_address,
    payment_program,
    witness_script_program,
)

PUBLIC = bytes.fromhex(
    "03a527c08aeb86e99f6a4019d9bcd38290a598d7287fcca929a684004ed8d41d39"
)
MAINNET_ADDRESS = "hs1q79vn7nsmua98v4gme98w0a07rgrvvxy9d93qw8"


class HnsAddressTest(unittest.TestCase):
    def test_hsd_account_zero_receive_vector(self):
        program = payment_program(PUBLIC)
        self.assertEqual(encode_v0_address("mainnet", program), MAINNET_ADDRESS)
        self.assertEqual(decode_v0_address("mainnet", MAINNET_ADDRESS).program, program)

    def test_network_and_script_hash_are_distinct(self):
        script = b"\x51\x75\x51"
        script_address = encode_v0_address("regtest", witness_script_program(script))
        self.assertTrue(script_address.startswith("rs1q"))
        self.assertEqual(len(decode_v0_address("regtest", script_address).program), 32)
        with self.assertRaises(ValueError):
            decode_v0_address("testnet", MAINNET_ADDRESS)


if __name__ == "__main__":
    unittest.main()
