# -*- coding: utf-8 -*-

# Copyright (c) 2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os
import select
import subprocess


def createDCRWallet(args, hex_seed, logging, delay_event):
    logging.info('Creating DCR wallet')
    (pipe_r, pipe_w) = os.pipe()  # subprocess.PIPE is buffered, blocks when read
    p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=pipe_w, stderr=pipe_w)

    try:
        while p.poll() is None:
            while len(select.select([pipe_r], [], [], 0)[0]) == 1:
                buf = os.read(pipe_r, 1024).decode('utf-8')
                logging.debug(f'dcrwallet {buf}')
                response = None
                if 'Use the existing configured private passphrase' in buf:
                    response = b'y\n'
                elif 'Do you want to add an additional layer of encryption' in buf:
                    response = b'n\n'
                elif 'Do you have an existing wallet seed' in buf:
                    response = b'y\n'
                elif 'Enter existing wallet seed' in buf:
                    response = (hex_seed + '\n').encode('utf-8')
                elif 'Seed input successful' in buf:
                    pass
                elif 'Upgrading database from version' in buf:
                    pass
                elif 'Ticket commitments db upgrade done' in buf:
                    pass
                else:
                    raise ValueError(f'Unexpected output: {buf}')
                if response is not None:
                    p.stdin.write(response)
                    p.stdin.flush()
            delay_event.wait(0.1)
    except Exception as e:
        logging.error(f'dcrwallet --create failed: {e}')
    finally:
        if p.poll() is None:
            p.terminate()
        os.close(pipe_r)
        os.close(pipe_w)
        p.stdin.close()
