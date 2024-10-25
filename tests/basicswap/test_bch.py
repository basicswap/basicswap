import unittest

from basicswap.contrib.test_framework.script import CScript
from basicswap.interface.bch import BCHInterface
from basicswap.util import ensure

bch_lock_spend_tx = '0200000001bfc6bbb47851441c7827059ae337a06aa9064da7f9537eb9243e45766c3dd34c00000000d8473045022100a0161ea14d3b41ed41250c8474fc8ec6ce1cab8df7f401e69ecf77c2ab63d82102207a2a57ddf2ea400e09ea059f3b261da96f5098858b17239931f3cc2fb929bb2a4c8ec3519dc4519d02e80300c600cc949d00ce00d18800cf00d28800d000d39d00cb641976a91481ec21969399d15c26af089d5db437ead066c5ba88ac00cd788821024ffcc0481629866671d89f05f3da813a2aacec1b52e69b8c0c586b665f5d4574ba6752b27523aa20df65a90e9becc316ff5aca44d4e06dfaade56622f32bafa197aba706c5e589758700cd87680000000001251cde06000000001976a91481ec21969399d15c26af089d5db437ead066c5ba88ac00000000'
bch_lock_script = 'c3519dc4519d02e80300c600cc949d00ce00d18800cf00d28800d000d39d00cb641976a91481ec21969399d15c26af089d5db437ead066c5ba88ac00cd788821024ffcc0481629866671d89f05f3da813a2aacec1b52e69b8c0c586b665f5d4574ba6752b27523aa20df65a90e9becc316ff5aca44d4e06dfaade56622f32bafa197aba706c5e589758700cd8768'
bch_lock_spend_script = '473045022100a0161ea14d3b41ed41250c8474fc8ec6ce1cab8df7f401e69ecf77c2ab63d82102207a2a57ddf2ea400e09ea059f3b261da96f5098858b17239931f3cc2fb929bb2a4c8ec3519dc4519d02e80300c600cc949d00ce00d18800cf00d28800d000d39d00cb641976a91481ec21969399d15c26af089d5db437ead066c5ba88ac00cd788821024ffcc0481629866671d89f05f3da813a2aacec1b52e69b8c0c586b665f5d4574ba6752b27523aa20df65a90e9becc316ff5aca44d4e06dfaade56622f32bafa197aba706c5e589758700cd8768'
bch_lock_swipe_script = '4c8fc3519dc4519d02e80300c600cc949d00ce00d18800cf00d28800d000d39d00cb641976a9141ab50aedd2e48297073f0f6eef46f97b37c9354e88ac00cd7888210234fe304a5b129b8265c177c92aa40b7840e8303f8b0fcca2359023163c7c2768ba670120b27523aa20191b09e40d1277fa14fea1e9b41e4fcc4528c9cb77e39e1b7b1a0b3332180cb78700cd8768'

coin_settings = {'rpcport': 0, 'rpcauth': 'none', 'blocks_confirmed': 1, 'conf_target': 1, 'use_segwit': False, 'connection_type': 'rpc'}

class TestXmrBchSwapInterface(unittest.TestCase):
    # def test_generate_script(self):    
    #     out_1 = bytes.fromhex('a9147171b53baf87efc9c78ffc0e37a78859cebaae4a87')
    #     out_2 = bytes.fromhex('a9147171b53baf87efc9c78ffc0e37a78859cebaae4a87')
    #     public_key = bytes.fromhex('03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556')

    #     ci = BCHInterface(coin_settings, "regtest")
    #     print(ci.genScriptLockTxScript(None, 1000, out_1, out_2, public_key, 2).hex())

    def test_extractScriptLockScriptValues(self):
        ci = BCHInterface(coin_settings, "regtest")

        script_bytes = CScript(bytes.fromhex(bch_lock_script))
        ci.extractScriptLockScriptValues(script_bytes)
        
        script_bytes = CScript(bytes.fromhex(bch_lock_spend_script))
        signature, mining_fee, out_1, out_2, public_key, timelock = ci.extractScriptLockScriptValuesFromScriptSig(script_bytes)
        ensure(signature is not None, 'signature not present')

        script_bytes = CScript(bytes.fromhex(bch_lock_swipe_script))
        signature, mining_fee, out_1, out_2, public_key, timelock = ci.extractScriptLockScriptValuesFromScriptSig(script_bytes)
        ensure(signature is None, 'signature present')
