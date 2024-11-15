# -*- coding: utf-8 -*-

# Copyright (c) 2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.


OP_0 = 0x00
OP_DATA_1 = 0x01
OP_1NEGATE = 0x4F
OP_1 = 0x51
OP_IF = 0x63
OP_ELSE = 0x67
OP_ENDIF = 0x68
OP_DROP = 0x75
OP_DUP = 0x76
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
OP_PUSHDATA1 = 0x4C
OP_PUSHDATA2 = 0x4D
OP_PUSHDATA4 = 0x4E
OP_HASH160 = 0xA9
OP_CHECKSIG = 0xAC
OP_CHECKMULTISIG = 0xAE
OP_CHECKSEQUENCEVERIFY = 0xB2


def push_script_data(data_array: bytearray, data: bytes) -> None:
    len_data: int = len(data)

    if len_data == 0 or (len_data == 1 and data[0] == 0):
        data_array += bytes((OP_0,))
        return
    if len_data == 1 and data[0] <= 16:
        data_array += bytes((OP_1 - 1 + data[0],))
        return
    if len_data == 1 and data[0] == 0x81:
        data_array += bytes((OP_1NEGATE,))
        return

    if len_data < OP_PUSHDATA1:
        data_array += len_data.to_bytes(1, "little")
    elif len_data <= 0xFF:
        data_array += bytes((OP_PUSHDATA1, len_data))
    elif len_data <= 0xFFFF:
        data_array += bytes((OP_PUSHDATA2,)) + len_data.to_bytes(2, "little")
    else:
        data_array += bytes((OP_PUSHDATA4,)) + len_data.to_bytes(4, "little")

    data_array += data
