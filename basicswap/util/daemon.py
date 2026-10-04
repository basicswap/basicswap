# -*- coding: utf-8 -*-

# Copyright (c) 2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.


class Daemon:
    __slots__ = ("handle", "files", "name", "running")

    def __init__(self, handle, files, name):
        self.handle = handle
        self.files = files
        self.name = name
        self.running = True

    def readOutput(self, max_lines: int = 10) -> str:
        if self.handle.stderr is not None:
            output = self.handle.stderr.read().decode("utf-8", errors="replace")
        elif len(self.files) > 0:
            with open(self.files[0].name, errors="replace") as fp:
                output = fp.read()
        else:
            return ""
        return "\n".join(output.strip().splitlines()[-max_lines:])
