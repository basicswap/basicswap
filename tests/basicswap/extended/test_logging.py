#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os
import shutil
import unittest

from basicswap.util.logging import trimLogFile


class Test(unittest.TestCase):
    def test_log_truncation(self):

        test_dir: str = "/tmp/bsx_test"
        if not os.path.isdir(test_dir):
            os.makedirs(test_dir)
        file_path: str = os.path.join(test_dir, "large.log")
        with open(file_path, "w") as fp:
            for i in range(1000000):
                fp.write(f"Basicswap test log line {i}\n")

        start_size = os.path.getsize(file_path)

        file_path2: str = os.path.join(test_dir, "test2.log")
        shutil.copyfile(file_path, file_path2)

        trimLogFile(file_path2, 0)
        file_path2_size = os.path.getsize(file_path2)
        assert file_path2_size == 20

        file_path3: str = os.path.join(test_dir, "test3.log")
        shutil.copyfile(file_path, file_path3)
        trimLogFile(file_path3, 70000)
        file_path3_size = os.path.getsize(file_path3)
        assert file_path3_size == 52503

        file_path4: str = os.path.join(test_dir, "test4.log")
        shutil.copyfile(file_path, file_path4)
        trimLogFile(file_path4, 70000, 0)
        file_path4_size = os.path.getsize(file_path4)
        assert file_path4_size == 70018  # Extra bytes for truncated message

        file_path5: str = os.path.join(test_dir, "test5.log")
        shutil.copyfile(file_path, file_path5)
        trimLogFile(file_path5, start_size - 7000)
        file_path5_size = os.path.getsize(file_path5)
        assert file_path5_size == 23161422  # ~1/4 of total size less


if __name__ == "__main__":
    unittest.main()
