"""hns-rs hns-swap v1 fixture and fail-closed funding checks."""

import unittest
from dataclasses import replace

from basicswap.interface.hns import HNS_MAX_MONEY
from basicswap.interface.hns.htlc import HnsHtlc
from basicswap.interface.hns.transaction import HnsCovenant, HnsTransaction

# crates/hns-swap/fixtures/protocol-v1/hns-swap-v1.txt in hns-rs 0.4.1.
DESCRIPTOR = bytes.fromhex(
    "010093c36e5b1111111111111111111111111111111111111111111111111111111111111111"
    "404b4c000000000084126d0dd850199be29021aadbaee68cb9199047b1cb7ec9894ddb1e3562783c"
    "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619"
    "0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c20a10700"
)
SCRIPT = bytes.fromhex(
    "63a82084126d0dd850199be29021aadbaee68cb9199047b1cb7ec9894ddb1e3562783c"
    "882102eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619"
    "670320a107b175210324653eac434488002cc06bbfb7f10fe18991e35f9fe43"
    "02dbea6d2353dc0ab1c68ac"
)
FUNDING_TRANSACTION = bytes.fromhex(
    "01000000012222222222222222222222222222222222222222222222222222222222222222"
    "03000000ffffffff01404b4c0000000000002023c2a34d907f099fe7dec5bf9228"
    "1578b519ab9a802b3b629eeb4c976d1c1a1c"
    "00000000000000"
)


class HnsHtlcTest(unittest.TestCase):
    def descriptor(self):
        return HnsHtlc.decode(DESCRIPTOR, 0x5B6EC393, bytes.fromhex("11" * 32))

    def test_hns_swap_v1_fixture(self):
        descriptor = self.descriptor()
        self.assertEqual(descriptor.encode(), DESCRIPTOR)
        self.assertEqual(
            descriptor.descriptor_hash().hex(),
            "93d2e4d84d43df867c0e99e6864feac6317992a57b96e17cf851278ba869cdfc",
        )
        self.assertEqual(descriptor.script(), SCRIPT)
        self.assertEqual(
            descriptor.funding_address().program.hex(),
            "23c2a34d907f099fe7dec5bf92281578b519ab9a802b3b629eeb4c976d1c1a1c",
        )
        descriptor.verify_funding_output(
            HnsTransaction.decode(FUNDING_TRANSACTION).outputs[0]
        )

    def test_network_and_contract_changes_are_rejected(self):
        with self.assertRaises(ValueError):
            HnsHtlc.decode(DESCRIPTOR, 0x5B6EC393, bytes(32))
        with self.assertRaises(ValueError):
            HnsHtlc.decode(
                b"\x02" + DESCRIPTOR[1:], 0x5B6EC393, bytes.fromhex("11" * 32)
            )
        descriptor = self.descriptor()
        output = HnsTransaction.decode(FUNDING_TRANSACTION).outputs[0]
        for bad_output in (
            replace(output, value=output.value - 1),
            replace(output, covenant=HnsCovenant(1)),
            replace(output, address=replace(output.address, program=bytes(32))),
        ):
            with self.assertRaises(ValueError):
                descriptor.verify_funding_output(bad_output)
        with self.assertRaises(ValueError):
            replace(
                descriptor, refund_public_key=descriptor.receiver_public_key
            ).script()
        with self.assertRaises(ValueError):
            replace(descriptor, receiver_public_key=b"\x02" + bytes(32)).script()
        with self.assertRaisesRegex(ValueError, "HTLC value"):
            replace(descriptor, value=HNS_MAX_MONEY + 1).encode()


if __name__ == "__main__":
    unittest.main()
