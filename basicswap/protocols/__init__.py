# -*- coding: utf-8 -*-

# Copyright (c) 2022-2023 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.script import (
    OpCodes,
)
from basicswap.interface.btc import (
    find_vout_for_address_from_txobj,
)


class ProtocolInterface:
    swap_type = None

    def getMockScript(self) -> bytearray:
        return bytearray([OpCodes.OP_RETURN, OpCodes.OP_1])

    def getMockScriptScriptPubkey(self, ci) -> bytearray:
        script = self.getMockScript()
        return (
            ci.getScriptDest(script)
            if ci._use_segwit
            else ci.get_p2sh_script_pubkey(script)
        )

    def getMockScriptAddr(self, ci):
        script = self.getMockScript()
        return (
            ci.encodeScriptDest(ci.getScriptDest(script))
            if ci._use_segwit
            else ci.encode_p2sh(script)
        )

    def findMockVout(self, ci, itx_decoded):
        mock_addr = self.getMockScriptAddr(ci)
        return find_vout_for_address_from_txobj(itx_decoded, mock_addr)
