# -*- coding: utf-8 -*-

# Copyright (c) 2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import logging
import os
from basicswap.util.crypto import (
    sha256,
)


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


def trimOpenLogFile(fp, max_bytes: int, add_trim_bytes: int = -1) -> bool:

    if add_trim_bytes < 0:
        # Set 1/4th of the total size by default
        add_trim_bytes = max_bytes // 4

    fp.seek(0, os.SEEK_END)
    end_pos: int = fp.tell()

    keep_bytes: int = max_bytes - add_trim_bytes
    if end_pos <= keep_bytes:
        return False
    if keep_bytes <= 0:
        fp.seek(0)
        fp.write("... File truncated.\n")
        fp.truncate()
        return True

    fp.seek(end_pos - keep_bytes)
    readahead_bytes = min(end_pos - keep_bytes, 4096)
    bytes_ahead = fp.read(readahead_bytes)

    # Find next newline
    for b in bytes_ahead:
        keep_bytes -= 1
        if b == "\n":
            break

    fp.seek(0)
    fp.write("... File truncated.\n")
    write_pos: int = fp.tell()
    bytes_moved: int = 0

    while bytes_moved < keep_bytes:
        chunk_size: int = min(end_pos - bytes_moved, 8096)
        fp.seek(end_pos - (keep_bytes - bytes_moved))

        data_chunk = fp.read(chunk_size)
        fp.seek(write_pos)
        fp.write(data_chunk)
        write_pos += chunk_size
        bytes_moved += chunk_size

    fp.truncate()
    return True


def trimLogFile(filepath, max_bytes: int, add_trim_bytes: int = -1) -> bool:
    if os.path.getsize(filepath) <= max_bytes:
        return False

    with open(filepath, "r+") as fp:
        return trimOpenLogFile(fp, max_bytes, add_trim_bytes)
