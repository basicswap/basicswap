# -*- coding: utf-8 -*-

# Copyright (c) 2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.


from basicswap.contrib.test_framework.script import CScriptOp


OP_TXINPUTCOUNT = CScriptOp(0xc3)
OP_1 = CScriptOp(0x51)
OP_NUMEQUALVERIFY = CScriptOp(0x9d)
OP_TXOUTPUTCOUNT = CScriptOp(0xc4)
OP_0 = CScriptOp(0x00)
OP_UTXOVALUE = CScriptOp(0xc6)
OP_OUTPUTVALUE = CScriptOp(0xcc)
OP_SUB = CScriptOp(0x94)
OP_UTXOTOKENCATEGORY = CScriptOp(0xce)
OP_OUTPUTTOKENCATEGORY = CScriptOp(0xd1)
OP_EQUALVERIFY = CScriptOp(0x88)
OP_UTXOTOKENCOMMITMENT = CScriptOp(0xcf)
OP_OUTPUTTOKENCOMMITMENT = CScriptOp(0xd2)
OP_UTXOTOKENAMOUNT = CScriptOp(0xd0)
OP_OUTPUTTOKENAMOUNT = CScriptOp(0xd3)
OP_INPUTSEQUENCENUMBER = CScriptOp(0xcb)
OP_NOTIF = CScriptOp(0x64)
OP_OUTPUTBYTECODE = CScriptOp(0xcd)
OP_OVER = CScriptOp(0x78)
OP_CHECKDATASIG = CScriptOp(0xba)
OP_CHECKDATASIGVERIFY = CScriptOp(0xbb)
OP_ELSE = CScriptOp(0x67)
OP_CHECKSEQUENCEVERIFY = CScriptOp(0xb2)
OP_DROP = CScriptOp(0x75)
OP_EQUAL = CScriptOp(0x87)
OP_ENDIF = CScriptOp(0x68)
OP_HASH256 = CScriptOp(0xaa)
OP_PUSHBYTES_32 = CScriptOp(0x20)
OP_DUP = CScriptOp(0x76)
OP_HASH160 = CScriptOp(0xa9)
OP_CHECKSIG = CScriptOp(0xac)
OP_SHA256 = CScriptOp(0xa8)
OP_VERIFY = CScriptOp(0x69)
