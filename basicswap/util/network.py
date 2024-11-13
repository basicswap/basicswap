# -*- coding: utf-8 -*-

# Copyright (c) 2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import contextlib
import ipaddress
import os
import time

from urllib.error import ContentTooShortError
from urllib.parse import _splittype
from urllib.request import Request, urlopen


def is_private_ip_address(addr: str):
    if addr == 'localhost':
        return True
    if addr.endswith('.local'):
        return True
    try:
        return ipaddress.ip_address(addr).is_private
    except Exception:
        return False


def make_reporthook(read_start: int, logger):
    read = read_start  # Number of bytes read so far
    last_percent_str = ''
    time_last = time.time()
    read_last = read_start
    display_last = time_last
    abo = 7
    average_buffer = [-1] * 8

    if read_start > 0:
        logger.info(f'Attempting to resume from byte {read_start}')

    def reporthook(blocknum, blocksize, totalsize):
        nonlocal read, last_percent_str, time_last, read_last, display_last, read_start
        nonlocal average_buffer, abo, logger
        read += blocksize

        # totalsize excludes read_start
        use_size = totalsize + read_start
        dl_complete: bool = totalsize > 0 and read >= use_size
        time_now = time.time()
        time_delta = time_now - time_last
        if time_delta < 4.0 and not dl_complete:
            return

        # Avoid division by zero by picking a value
        if time_delta <= 0.0:
            time_delta = 0.01

        bytes_delta = read - read_last
        time_last = time_now
        read_last = read
        bits_per_second = (bytes_delta * 8) / time_delta

        abo = 0 if abo >= 7 else abo + 1
        average_buffer[abo] = bits_per_second

        samples = 0
        average_bits_per_second = 0
        for sample in average_buffer:
            if sample < 0:
                continue
            average_bits_per_second += sample
            samples += 1
        average_bits_per_second /= samples

        speed_str: str
        if average_bits_per_second > 1000 ** 3:
            speed_str = '{:.2f} Gbps'.format(average_bits_per_second / (1000 ** 3))
        elif average_bits_per_second > 1000 ** 2:
            speed_str = '{:.2f} Mbps'.format(average_bits_per_second / (1000 ** 2))
        else:
            speed_str = '{:.2f} kbps'.format(average_bits_per_second / 1000)

        if totalsize > 0:
            percent_str = '%5.0f%%' % (read * 1e2 / use_size)
            if percent_str != last_percent_str or time_now - display_last > 10:
                logger.info(percent_str + '  ' + speed_str)
                last_percent_str = percent_str
                display_last = time_now
        else:
            logger.info(f'Read {read}, {speed_str}')
    return reporthook


def urlretrieve(url, filename, reporthook=None, data=None, resume_from=0):
    '''urlretrieve with resume
    '''
    url_type, path = _splittype(url)

    req = Request(url)
    if resume_from > 0:
        req.add_header('Range', f'bytes={resume_from}-')
    with contextlib.closing(urlopen(req)) as fp:
        headers = fp.info()

        # Just return the local path and the "headers" for file://
        # URLs. No sense in performing a copy unless requested.
        if url_type == "file" and not filename:
            return os.path.normpath(path), headers

        with open(filename, 'ab' if resume_from > 0 else 'wb') as tfp:
            result = filename, headers
            bs = 1024 * 8
            size = -1
            read = resume_from
            blocknum = 0
            range_from = 0
            if "content-length" in headers:
                size = int(headers["Content-Length"])
            if "Content-Range" in headers:
                range_str = headers["Content-Range"]
                offset = range_str.find('-')
                range_from = int(range_str[6:offset])
            if resume_from != range_from:
                raise ValueError('Download is not resuming from the expected byte')

            if reporthook:
                reporthook(blocknum, bs, size)

            while True:
                block = fp.read(bs)
                if not block:
                    break
                read += len(block)
                tfp.write(block)
                blocknum += 1
                if reporthook:
                    reporthook(blocknum, bs, size)

    if size >= 0 and read < size:
        raise ContentTooShortError(
            "retrieval incomplete: got only %i out of %i bytes"
            % (read, size), result)

    return result
