# MoneroPy - A python toolbox for Monero
# Copyright (C) 2016 The MoneroPy Developers.
#
# MoneroPy is released under the BSD 3-Clause license. Use and redistribution of
# this software is subject to the license terms in the LICENSE file found in the
# top-level directory of this distribution.

__alphabet = [ord(s) for s in '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz']
__b58base = 58
__UINT64MAX = 2**64
__encodedBlockSizes = [0, 2, 3, 5, 6, 7, 9, 10, 11]
__fullBlockSize = 8
__fullEncodedBlockSize = 11

def _hexToBin(hex):
    if len(hex) % 2 != 0:
        return "Hex string has invalid length!"
    return [int(hex[i*2:i*2+2], 16) for i in range(len(hex)//2)]

def _binToHex(bin):
    return "".join([("0" + hex(int(bin[i])).split('x')[1])[-2:] for i in range(len(bin))])

def _strToBin(a):
    return [ord(s) for s in a]

def _binToStr(bin):
    return ''.join([chr(bin[i]) for i in range(len(bin))])

def _uint8be_to_64(data):
    l_data = len(data)

    if l_data < 1 or l_data > 8:
        return "Invalid input length"

    res = 0
    switch = 9 - l_data
    for i in range(l_data):
        if switch == 1:
            res = res << 8 | data[i]
        elif switch == 2:
            res = res << 8 | data[i]
        elif switch == 3:
            res = res << 8 | data[i]
        elif switch == 4:
            res = res << 8 | data[i]
        elif switch == 5:
            res = res << 8 | data[i]
        elif switch == 6:
            res = res << 8 | data[i]
        elif switch == 7:
            res = res << 8 | data[i]
        elif switch == 8:
            res = res << 8 | data[i]
        else:
            return "Impossible condition"
    return res

def _uint64_to_8be(num, size):
    res = [0] * size;
    if size < 1 or size > 8:
        return "Invalid input length"

    twopow8 = 2**8
    for i in range(size-1,-1,-1):
        res[i] = num % twopow8
        num = num // twopow8

    return res

def encode_block(data, buf, index):
    l_data = len(data)

    if l_data < 1 or l_data > __fullEncodedBlockSize:
        return "Invalid block length: " + str(l_data)

    num = _uint8be_to_64(data)
    i = __encodedBlockSizes[l_data] - 1

    while num > 0:
        remainder = num % __b58base
        num = num // __b58base
        buf[index+i] = __alphabet[remainder];
        i -= 1

    return buf

def encode(hex):
    '''Encode hexadecimal string as base58 (ex: encoding a Monero address).'''
    data = _hexToBin(hex)
    l_data = len(data)

    if l_data == 0:
        return ""

    full_block_count = l_data // __fullBlockSize
    last_block_size = l_data % __fullBlockSize
    res_size = full_block_count * __fullEncodedBlockSize + __encodedBlockSizes[last_block_size]

    res = [0] * res_size
    for i in range(res_size):
        res[i] = __alphabet[0]

    for i in range(full_block_count):
        res = encode_block(data[(i*__fullBlockSize):(i*__fullBlockSize+__fullBlockSize)], res, i * __fullEncodedBlockSize)

    if last_block_size > 0:
        res = encode_block(data[(full_block_count*__fullBlockSize):(full_block_count*__fullBlockSize+last_block_size)], res, full_block_count * __fullEncodedBlockSize)

    return _binToStr(res)

def decode_block(data, buf, index):
    l_data = len(data)

    if l_data < 1 or l_data > __fullEncodedBlockSize:
        return "Invalid block length: " + l_data

    res_size = __encodedBlockSizes.index(l_data)
    if res_size <= 0:
        return "Invalid block size"

    res_num = 0
    order = 1
    for i in range(l_data-1, -1, -1):
        digit = __alphabet.index(data[i])
        if digit < 0:
            return "Invalid symbol"

        product = order * digit + res_num
        if product > __UINT64MAX:
            return "Overflow"

        res_num = product
        order = order * __b58base

    if res_size < __fullBlockSize and 2**(8 * res_size) <= res_num:
        return "Overflow 2"

    tmp_buf = _uint64_to_8be(res_num, res_size)
    for i in range(len(tmp_buf)):
        buf[i+index] = tmp_buf[i]

    return buf

def decode(enc):
    '''Decode a base58 string (ex: a Monero address) into hexidecimal form.'''
    enc = _strToBin(enc)
    l_enc = len(enc)

    if l_enc == 0:
        return ""

    full_block_count = l_enc // __fullEncodedBlockSize
    last_block_size = l_enc % __fullEncodedBlockSize
    last_block_decoded_size = __encodedBlockSizes.index(last_block_size)

    if last_block_decoded_size < 0:
        return "Invalid encoded length"

    data_size = full_block_count * __fullBlockSize + last_block_decoded_size

    data = [0] * data_size
    for i in range(full_block_count):
        data = decode_block(enc[(i*__fullEncodedBlockSize):(i*__fullEncodedBlockSize+__fullEncodedBlockSize)], data, i * __fullBlockSize)

    if last_block_size > 0:
        data = decode_block(enc[(full_block_count*__fullEncodedBlockSize):(full_block_count*__fullEncodedBlockSize+last_block_size)], data, full_block_count * __fullBlockSize)

    return _binToHex(data)
