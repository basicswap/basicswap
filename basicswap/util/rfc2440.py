# -*- coding: utf-8 -*-

import hashlib
import secrets


def rfc2440_hash_password(password, salt=None):
    # Match tor --hash-password
    # secret_to_key_rfc2440

    EXPBIAS = 6
    c = 96
    count = (16 + (c & 15)) << ((c >> 4) + EXPBIAS)

    if salt is None:
        salt = secrets.token_bytes(8)
    assert len(salt) == 8

    hashbytes = salt + password.encode('utf-8')
    len_hashbytes = len(hashbytes)
    h = hashlib.sha1()

    while count > 0:
        if count >= len_hashbytes:
            h.update(hashbytes)
            count -= len_hashbytes
            continue
        h.update(hashbytes[:count])
        break
    rv = '16:' + salt.hex() + '60' + h.hexdigest()
    return rv.upper()
