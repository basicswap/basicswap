# -*- coding: utf-8 -*-

# Copyright (c) 2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.script import (
    OpCodes,
)
from basicswap.util.script import (
    getP2WSH,
)


class ProtocolInterface:
    swap_type = None

    def getFundedInitiateTxTemplate(self, ci, amount: int, sub_fee: bool) -> bytes:
        raise ValueError('base class')

    def getMockScript(self) -> bytearray:
        return bytearray([
            OpCodes.OP_RETURN, OpCodes.OP_1])

    def getMockScriptScriptPubkey(self, ci) -> bytearray:
        script = self.getMockScript()
        return ci.get_p2wsh_script_pubkey(script) if ci._use_segwit else ci.get_p2sh_script_pubkey(script)

    def getMockAddrTo(self, ci):
        script = self.getMockScript()
        return ci.encode_p2wsh(getP2WSH(script)) if ci._use_segwit else ci.encode_p2sh(script)
