# -*- coding: utf-8 -*-

# Copyright (c) 2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.


class Daemon:
    __slots__ = ("handle", "files")

    def __init__(self, handle, files):
        self.handle = handle
        self.files = files
