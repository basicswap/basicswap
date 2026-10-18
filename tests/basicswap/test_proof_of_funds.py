# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import unittest

from basicswap.interface.btc.btc import BTCInterface
from basicswap.interface.dcr.dcr import DCRInterface
from basicswap.interface.firo.firo import FIROInterface
from basicswap.interface.nav.nav import NAVInterface
from basicswap.util.crypto import hash160
from tests.basicswap.util.common import REQUIRED_SETTINGS

ADDRESS = "mnnneadnnywzceaadkfnzknnnnnnnnnnnn"
SIGNATURE = b"sig"
COMMIT_BYTES = b"\x01\x02"


def make_interface(connection_type="none"):
    settings = dict(REQUIRED_SETTINGS)
    settings.update(
        {
            "rpcport": 0,
            "rpcauth": "none",
            "connection_type": connection_type,
            "use_segwit": False,
        }
    )
    ci = BTCInterface(settings, "regtest")
    ci.verifyMessage = lambda address, message, signature: True
    return ci


class ElectrumBalanceBackend:
    def __init__(self, unspents=None, error=None):
        self._unspents = unspents
        self._error = error

    def getUnspentOutputs(self, addresses):
        if self._error is not None:
            raise self._error
        return self._unspents


class VerifyProofOfFundsTest(unittest.TestCase):
    def test_invalid_signature_raises(self):
        ci = make_interface()
        ci.verifyMessage = lambda address, message, signature: False
        with self.assertRaisesRegex(ValueError, "signature invalid"):
            ci.verifyProofOfFunds(ADDRESS, SIGNATURE, [], COMMIT_BYTES)

    def test_electrum_returns_balance(self):
        ci = make_interface("electrum")
        ci._backend = ElectrumBalanceBackend(
            unspents=[{"value": 5000}, {"value": 6000}]
        )
        rv = ci.verifyProofOfFunds(ADDRESS, SIGNATURE, [], COMMIT_BYTES)
        self.assertEqual(rv, 11000)

    def test_electrum_failure_raises(self):
        ci = make_interface("electrum")
        ci._backend = ElectrumBalanceBackend(error=ConnectionError("server gone"))
        with self.assertRaisesRegex(ValueError, "balance check failed"):
            ci.verifyProofOfFunds(ADDRESS, SIGNATURE, [], COMMIT_BYTES)

    def test_rpc_returns_balance(self):
        ci = make_interface()
        ci.getUTXOBalance = lambda address: 12345
        rv = ci.verifyProofOfFunds(ADDRESS, SIGNATURE, [], COMMIT_BYTES)
        self.assertEqual(rv, 12345)

    def test_rpc_failure_raises(self):
        ci = make_interface()

        def fail(address):
            raise ConnectionError("rpc down")

        ci.getUTXOBalance = fail
        with self.assertRaisesRegex(ValueError, "balance check failed"):
            ci.verifyProofOfFunds(ADDRESS, SIGNATURE, [], COMMIT_BYTES)


SIGNER_PKH = bytes(range(20))
OTHER_PKH = bytes(range(20, 40))


def p2pkh(pkh: bytes) -> bytes:
    return bytes((0x76, 0xA9, 20)) + pkh + bytes((0x88, 0xAC))


def p2sh_p2wpkh(pkh: bytes) -> bytes:
    return bytes((0xA9, 20)) + hash160(bytes((0x00, 20)) + pkh) + bytes((0x87,))


def make_outpoint_interface(cls, scripts: dict, use_segwit: bool = False):
    settings = dict(REQUIRED_SETTINGS)
    settings.update({"rpcport": 0, "rpcauth": "none", "use_segwit": use_segwit})
    ci = cls(settings, "regtest")
    ci.verifyMessage = lambda address, message, signature: True

    def rpc(method, params=None):
        assert method == "gettxout"
        script = scripts[(bytes.fromhex(params[0]), params[1])]
        return {"value": 1.0, "scriptPubKey": {"hex": script.hex()}}

    ci.rpc = rpc
    return ci


class VerifyOutpointProofOfFundsTest(unittest.TestCase):
    def check_coin(self, cls, signer_scripts, tree=()):
        own = [(bytes([i + 1]) * 32, i) + tree for i in range(len(signer_scripts))]
        other = (bytes([9]) * 32, 0) + tree
        scripts = {o[:2]: s for o, s in zip(own, signer_scripts)}
        scripts[other[:2]] = p2pkh(OTHER_PKH)
        ci = make_outpoint_interface(cls, scripts)
        address = ci.pkh_to_address(SIGNER_PKH)

        rv = ci.verifyProofOfFunds(address, SIGNATURE, own, COMMIT_BYTES)
        self.assertEqual(rv, len(own) * ci.make_int(1.0))
        with self.assertRaisesRegex(ValueError, "does not pay the signing address"):
            ci.verifyProofOfFunds(address, SIGNATURE, own + [other], COMMIT_BYTES)
        with self.assertRaisesRegex(ValueError, "Duplicate proof of funds outpoint"):
            ci.verifyProofOfFunds(address, SIGNATURE, own + own[:1], COMMIT_BYTES)

    def test_nav(self):
        self.check_coin(NAVInterface, [p2pkh(SIGNER_PKH), p2sh_p2wpkh(SIGNER_PKH)])

    def test_firo(self):
        self.check_coin(FIROInterface, [p2pkh(SIGNER_PKH), p2pkh(SIGNER_PKH)])

    def test_dcr(self):
        self.check_coin(DCRInterface, [p2pkh(SIGNER_PKH), p2pkh(SIGNER_PKH)], (0,))

    def test_nav_signs_for_the_chosen_address(self):
        settings = dict(REQUIRED_SETTINGS)
        settings.update({"rpcport": 0, "rpcauth": "none", "use_segwit": True})
        ci = NAVInterface(settings, "regtest")
        funded = ci.encodeSegwitAddress(SIGNER_PKH)
        validated = []

        def rpc(method, params=None):
            if method == "listunspent":
                # The address that can't cover the amount is listed last
                return [
                    {
                        "spendable": True,
                        "address": funded,
                        "amount": 2.0,
                        "txid": "11" * 32,
                        "vout": 0,
                    },
                    {
                        "spendable": True,
                        "address": ci.encodeSegwitAddress(OTHER_PKH),
                        "amount": 0.1,
                        "txid": "22" * 32,
                        "vout": 0,
                    },
                ]
            if method == "validateaddress":
                validated.append(params[0])
                pkh = SIGNER_PKH if params[0] == funded else OTHER_PKH
                return {"isscript": True, "hex": "0014" + pkh.hex()}
            assert method == "signmessage"
            return "sig"

        ci.rpc = rpc
        sign_for_addr, _, _ = ci.getProofOfFunds(ci.make_int(1.0), COMMIT_BYTES)
        self.assertEqual(validated, [funded])
        self.assertEqual(sign_for_addr, ci.pkh_to_address(SIGNER_PKH))


if __name__ == "__main__":
    unittest.main()
