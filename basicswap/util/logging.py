# -*- coding: utf-8 -*-

# Copyright (c) 2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import logging
from enum import IntEnum, auto
from basicswap.util.crypto import (
    sha256,
)


class LogCategories(IntEnum):
    NET = auto()


class BSXLogger(logging.Logger):
    def __init__(self, name):
        super().__init__(name)
        self.safe_logs = False
        self.safe_logs_prefix = b""

    def addr(self, addr: str) -> str:
        if self.safe_logs:
            return (
                "A_"
                + sha256(self.safe_logs_prefix + addr.encode(encoding="utf-8"))[
                    :8
                ].hex()
            )
        return addr

    def id(self, concept_id: bytes, prefix: str = "") -> str:
        if concept_id is None:
            return prefix + "None"
        if isinstance(concept_id, str):
            concept_id = bytes.fromhex(concept_id)
        if self.safe_logs:
            return (prefix if len(prefix) > 0 else "_") + sha256(
                self.safe_logs_prefix + concept_id
            )[:8].hex()
        return prefix + concept_id.hex()

    def info_s(self, msg, *args, **kwargs):
        if self.safe_logs is False:
            self.info(msg, *args, **kwargs)
