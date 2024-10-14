import unittest

from basicswap.protocols.xmr_swap_1 import XmrBchSwapInterface


class TestXmrBchSwapInterface(unittest.TestCase):
    def test_generate_script(self):    
        out_1 = bytes.fromhex('a9147171b53baf87efc9c78ffc0e37a78859cebaae4a87')
        out_2 = bytes.fromhex('a9147171b53baf87efc9c78ffc0e37a78859cebaae4a87')
        public_key = bytes.fromhex('03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556')
        print(XmrBchSwapInterface().genScriptLockTxScript(None, 1000, out_1, out_2, public_key, 2).hex())
