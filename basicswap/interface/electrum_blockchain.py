# -*- coding: utf-8 -*-

# Copyright (C) 2011 thomasv@gitorious
# Copyright (C) 2012 thomasv@ecdsa.org
# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

# Ported from Electrum's blockchain.py, interface.py, verifier.py and
# transaction.py, with Electrum-LTC's retarget rule.

import os
import stat
import subprocess
import threading
from hashlib import sha256
from pathlib import Path

HEADER_SIZE = 80
CHUNK_SIZE = 2016
MAX_NUM_HEADERS_PER_REQUEST = 2016


class MissingHeader(Exception):
    pass


class InvalidHeader(Exception):
    pass


class RequestCorrupted(Exception):
    pass


class ChainConflict(Exception):
    pass


class MerkleVerificationFailure(Exception):
    pass


class MissingBlockHeader(MerkleVerificationFailure):
    pass


class MerkleRootMismatch(MerkleVerificationFailure):
    pass


class InnerNodeOfSpvProofIsValidTx(MerkleVerificationFailure):
    pass


class LeftSiblingDuplicate(MerkleVerificationFailure):
    pass


class ChainResolutionMode:
    CATCHUP = "catchup"
    BACKWARD = "backward"
    BINARY = "binary"
    FORK = "fork"
    NO_FORK = "no_fork"


def sha256d(data: bytes) -> bytes:
    return sha256(sha256(data).digest()).digest()


def hash_encode(x: bytes) -> str:
    return x[::-1].hex()


def hash_decode(x: str) -> bytes:
    return bytes.fromhex(x)[::-1]


def with_lock(func):
    def func_wrapper(self, *args, **kwargs):
        with self.lock:
            return func(self, *args, **kwargs)

    return func_wrapper


def make_dir(path: Path) -> None:
    if not path.exists():
        path.mkdir(parents=True)
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)


def ensure_sparse_file(file_path: Path, log=None) -> None:
    if os.name == "nt":
        try:
            subprocess.run(
                ["fsutil", "sparse", "setflag", str(file_path), "1"],
                check=True,
                capture_output=True,
            )
        except (subprocess.CalledProcessError, OSError) as e:
            if log:
                log.warning(f"error marking file {file_path} as sparse: {e}")


def serialize_header(header_dict: dict) -> bytes:
    s = (
        int.to_bytes(header_dict["version"], length=4, byteorder="little", signed=False)
        + bytes.fromhex(header_dict["prev_block_hash"])[::-1]
        + bytes.fromhex(header_dict["merkle_root"])[::-1]
        + int.to_bytes(
            int(header_dict["timestamp"]), length=4, byteorder="little", signed=False
        )
        + int.to_bytes(
            int(header_dict["bits"]), length=4, byteorder="little", signed=False
        )
        + int.to_bytes(
            int(header_dict["nonce"]), length=4, byteorder="little", signed=False
        )
    )
    return s


def deserialize_header(s: bytes, height: int) -> dict:
    if not s:
        raise InvalidHeader("Invalid header: {}".format(s))
    if len(s) != HEADER_SIZE:
        raise InvalidHeader("Invalid header length: {}".format(len(s)))
    h = {}
    h["version"] = int.from_bytes(s[0:4], byteorder="little")
    h["prev_block_hash"] = hash_encode(s[4:36])
    h["merkle_root"] = hash_encode(s[36:68])
    h["timestamp"] = int.from_bytes(s[68:72], byteorder="little")
    h["bits"] = int.from_bytes(s[72:76], byteorder="little")
    h["nonce"] = int.from_bytes(s[76:80], byteorder="little")
    h["block_height"] = height
    return h


def hash_header(header: dict | None) -> str:
    if header is None:
        return "0" * 64
    if header.get("prev_block_hash") is None:
        header["prev_block_hash"] = "00" * 32
    return hash_raw_header(serialize_header(header))


def hash_raw_header(header: bytes) -> str:
    assert isinstance(header, bytes)
    return hash_encode(sha256d(header))


class HeaderNet:
    def __init__(
        self,
        genesis: str,
        checkpoints: list,
        testnet: bool,
        max_target: int,
        first_target: int,
        target_timespan: int,
        pow_hash_header=hash_header,
        timestamp_before_chunk: bool = False,
    ):
        self.GENESIS = genesis
        self.CHECKPOINTS = checkpoints
        self.TESTNET = testnet
        self.MAX_TARGET = max_target
        self.FIRST_TARGET = first_target
        self.TARGET_TIMESPAN = target_timespan
        self.pow_hash_header = pow_hash_header
        self.timestamp_before_chunk = timestamp_before_chunk

    def max_checkpoint(self) -> int:
        return max(0, len(self.CHECKPOINTS) * CHUNK_SIZE - 1)


class BlockchainManager:
    def __init__(self, *, headers_dir: Path, net: HeaderNet, log):
        self.headers_dir = headers_dir
        self.forks_dir = headers_dir / "forks"
        self.net = net
        self.log = log
        make_dir(self.forks_dir)

        self.blockchains = {}
        self.blockchains_lock = threading.RLock()
        self.bhi_lock = threading.RLock()
        self.chainwork_cache = {"00" * 32: 0}

        self._read_blockchains()
        self._init_headers_file_for_best_chain()
        self.log.info(
            f"blockchains {list(map(lambda b: b.forkpoint, self.blockchains.values()))}"
        )

    def _read_blockchains(self):
        best_chain = Blockchain(
            bc_mgr=self,
            forkpoint=0,
            parent=None,
            forkpoint_hash=self.net.GENESIS,
            prev_hash=None,
        )
        self.blockchains[self.net.GENESIS] = best_chain

        if best_chain.height() > self.net.max_checkpoint():
            header_after_cp = best_chain.read_header(self.net.max_checkpoint() + 1)
            if not header_after_cp or not best_chain.can_connect(
                header_after_cp, check_height=False
            ):
                self.log.warning(
                    "[blockchain] deleting best chain. cannot connect header after last cp to last cp."
                )
                best_chain.path().unlink()
                best_chain.update_size()

        names = filter(
            lambda x: x.startswith("fork2_") and "." not in x,
            os.listdir(self.forks_dir),
        )
        names = sorted(names, key=lambda x: int(x.split("_")[1]))
        for filename in names:
            self._instantiate_chain(filename)

    def _instantiate_chain(self, filename: str):
        __, forkpoint, prev_hash, first_hash = filename.split("_")
        forkpoint = int(forkpoint)
        prev_hash = (64 - len(prev_hash)) * "0" + prev_hash
        first_hash = (64 - len(first_hash)) * "0" + first_hash
        if forkpoint <= self.net.max_checkpoint():
            self._delete_chain(filename, "deleting fork below max checkpoint")
            return
        for parent in self.blockchains.values():
            if parent.check_hash(forkpoint - 1, prev_hash):
                break
        else:
            self._delete_chain(filename, "cannot find parent for chain")
            return
        b = Blockchain(
            bc_mgr=self,
            forkpoint=forkpoint,
            parent=parent,
            forkpoint_hash=first_hash,
            prev_hash=prev_hash,
        )
        h = b.read_header(b.forkpoint)
        if first_hash != hash_header(h):
            self._delete_chain(filename, "incorrect first hash for chain")
            return
        if not b.parent.can_connect(h, check_height=False):
            self._delete_chain(filename, "cannot connect chain to parent")
            return
        chain_id = b.get_id()
        assert first_hash == chain_id, (first_hash, chain_id)
        self.blockchains[chain_id] = b

    def _delete_chain(self, filename: str, reason: str):
        self.log.info(f"[blockchain] deleting chain {filename}: {reason}")
        (self.forks_dir / filename).unlink()

    def _init_headers_file_for_best_chain(self):
        b = self.get_best_chain()
        filename = b.path()
        length = HEADER_SIZE * len(self.net.CHECKPOINTS) * CHUNK_SIZE
        if not filename.exists() or filename.stat().st_size < length:
            with open(filename, "wb") as f:
                if length > 0:
                    f.seek(length - 1)
                    f.write(b"\x00")
            ensure_sparse_file(filename, self.log)
        with b.lock:
            b.update_size()

    def get_best_chain(self) -> "Blockchain":
        return self.blockchains[self.net.GENESIS]

    def check_header(self, header: dict) -> "Blockchain | None":
        if type(header) is not dict:
            return None
        with self.blockchains_lock:
            chains = list(self.blockchains.values())
        for b in chains:
            if b.check_header(header):
                return b
        return None

    def can_connect(self, header: dict) -> "Blockchain | None":
        with self.blockchains_lock:
            chains = list(self.blockchains.values())
        for b in chains:
            if b.can_connect(header):
                return b
        return None


class Blockchain:
    def __init__(
        self,
        *,
        bc_mgr: BlockchainManager,
        forkpoint: int,
        parent: "Blockchain | None",
        forkpoint_hash: str,
        prev_hash: str | None,
    ):
        assert (
            isinstance(forkpoint_hash, str) and len(forkpoint_hash) == 64
        ), forkpoint_hash
        assert (prev_hash is None) or (
            isinstance(prev_hash, str) and len(prev_hash) == 64
        ), prev_hash
        if 0 < forkpoint <= bc_mgr.net.max_checkpoint():
            raise Exception(f"cannot fork below max checkpoint. forkpoint: {forkpoint}")
        self.bc_mgr = bc_mgr
        self.net = bc_mgr.net
        if parent is not None:
            assert bc_mgr is parent.bc_mgr
        self.forkpoint = forkpoint
        self.parent = parent
        self._forkpoint_hash = forkpoint_hash
        self._prev_hash = prev_hash
        self.lock = threading.RLock()
        self.update_size()

    @property
    def checkpoints(self):
        return self.net.CHECKPOINTS

    def get_max_child(self) -> int | None:
        children = self.get_direct_children()
        return max([x.forkpoint for x in children]) if children else None

    def get_max_forkpoint(self) -> int:
        mc = self.get_max_child()
        return mc if mc is not None else self.forkpoint

    def get_direct_children(self) -> list:
        with self.bc_mgr.blockchains_lock:
            return list(
                filter(lambda y: y.parent == self, self.bc_mgr.blockchains.values())
            )

    def get_parent_heights(self) -> dict:
        with self.lock, self.bc_mgr.blockchains_lock:
            result = {self: self.height()}
            chain = self
            while True:
                parent = chain.parent
                if parent is None:
                    break
                result[parent] = chain.forkpoint - 1
                chain = parent
            return result

    def get_height_of_last_common_block_with_chain(self, other_chain) -> int:
        last_common_block_height = 0
        our_parents = self.get_parent_heights()
        their_parents = other_chain.get_parent_heights()
        for chain in our_parents:
            if chain in their_parents:
                h = min(our_parents[chain], their_parents[chain])
                last_common_block_height = max(last_common_block_height, h)
        return last_common_block_height

    @with_lock
    def get_branch_size(self) -> int:
        return self.height() - self.get_max_forkpoint() + 1

    def check_header(self, header: dict) -> bool:
        header_hash = hash_header(header)
        height = header.get("block_height")
        return self.check_hash(height, header_hash)

    def check_hash(self, height: int, header_hash: str) -> bool:
        assert isinstance(header_hash, str) and len(header_hash) == 64, header_hash
        try:
            return header_hash == self.get_hash(height)
        except Exception:
            return False

    def fork(parent, header: dict) -> "Blockchain":
        if not parent.can_connect(header, check_height=False):
            raise Exception("forking header does not connect to parent chain")
        forkpoint = header.get("block_height")
        self = Blockchain(
            bc_mgr=parent.bc_mgr,
            forkpoint=forkpoint,
            parent=parent,
            forkpoint_hash=hash_header(header),
            prev_hash=parent.get_hash(forkpoint - 1),
        )
        self.assert_headers_file_available(parent.path())
        open(self.path(), "w+").close()
        self.save_header(header)
        chain_id = self.get_id()
        with parent.bc_mgr.blockchains_lock:
            parent.bc_mgr.blockchains[chain_id] = self
        return self

    @with_lock
    def height(self) -> int:
        return self.forkpoint + self.size() - 1

    @with_lock
    def size(self) -> int:
        return self._size

    @with_lock
    def update_size(self) -> None:
        p = self.path()
        self._size = os.path.getsize(p) // HEADER_SIZE if p.exists() else 0

    def verify_header(
        self,
        header: dict,
        prev_hash: str,
        target: int,
        expected_header_hash: str = None,
    ) -> None:
        _hash = hash_header(header)
        if expected_header_hash and expected_header_hash != _hash:
            raise InvalidHeader(
                "hash mismatches with expected: {} vs {}".format(
                    expected_header_hash, _hash
                )
            )
        if prev_hash != header.get("prev_block_hash"):
            raise InvalidHeader(
                "prev hash mismatch: %s vs %s"
                % (prev_hash, header.get("prev_block_hash"))
            )
        if self.net.TESTNET:
            return
        bits = self.target_to_bits(target)
        if bits != header.get("bits"):
            raise InvalidHeader("bits mismatch: %s vs %s" % (bits, header.get("bits")))
        _pow_hash = self.net.pow_hash_header(header)
        pow_hash_as_num = int.from_bytes(bytes.fromhex(_pow_hash), byteorder="big")
        if pow_hash_as_num > target:
            raise InvalidHeader(
                f"insufficient proof of work: {pow_hash_as_num} vs target {target}"
            )

    def verify_chunk(self, index: int, data: bytes) -> None:
        num = len(data) // HEADER_SIZE
        start_height = index * CHUNK_SIZE
        prev_hash = self.get_hash(start_height - 1)
        target = self.get_target(index - 1)
        for i in range(num):
            height = start_height + i
            try:
                expected_header_hash = self.get_hash(height)
            except MissingHeader:
                expected_header_hash = None
            raw_header = data[i * HEADER_SIZE : (i + 1) * HEADER_SIZE]
            header = deserialize_header(raw_header, index * CHUNK_SIZE + i)
            self.verify_header(header, prev_hash, target, expected_header_hash)
            prev_hash = hash_header(header)

    @with_lock
    def path(self) -> Path:
        if self.parent is None:
            return self.bc_mgr.headers_dir / "blockchain_headers"
        else:
            assert self.forkpoint > 0, self.forkpoint
            prev_hash = self._prev_hash.lstrip("0")
            first_hash = self._forkpoint_hash.lstrip("0")
            basename = f"fork2_{self.forkpoint}_{prev_hash}_{first_hash}"
            return self.bc_mgr.forks_dir / basename

    @with_lock
    def save_chunk(self, index: int, chunk: bytes):
        assert index >= 0, index
        chunk_within_checkpoint_region = index < len(self.checkpoints)
        if chunk_within_checkpoint_region and self.parent is not None:
            main_chain = self.bc_mgr.get_best_chain()
            main_chain.save_chunk(index, chunk)
            return

        delta_height = index * CHUNK_SIZE - self.forkpoint
        delta_bytes = delta_height * HEADER_SIZE
        if delta_bytes < 0:
            chunk = chunk[-delta_bytes:]
            delta_bytes = 0
        truncate = not chunk_within_checkpoint_region
        self.write(chunk, delta_bytes, truncate)
        self.swap_with_parent()

    def swap_with_parent(self) -> None:
        with self.lock, self.bc_mgr.blockchains_lock:
            cnt = 0
            while True:
                old_parent = self.parent
                if not self._swap_with_parent():
                    break
                cnt += 1
                if cnt > len(self.bc_mgr.blockchains):
                    raise Exception(f"swapping fork with parent too many times: {cnt}")
                for old_sibling in old_parent.get_direct_children():
                    if self.check_hash(
                        old_sibling.forkpoint - 1, old_sibling._prev_hash
                    ):
                        old_sibling.parent = self

    def _swap_with_parent(self) -> bool:
        if self.parent is None:
            return False
        if self.parent.get_chainwork() >= self.get_chainwork():
            return False
        self.bc_mgr.log.info(f"swapping {self.forkpoint} {self.parent.forkpoint}")
        parent_branch_size = self.parent.height() - self.forkpoint + 1
        forkpoint = self.forkpoint
        parent = self.parent
        child_old_id = self.get_id()
        parent_old_id = parent.get_id()
        self.assert_headers_file_available(self.path())
        child_old_name = self.path()
        with open(self.path(), "rb") as f:
            my_data = f.read()
        self.assert_headers_file_available(parent.path())
        assert forkpoint > parent.forkpoint, (
            f"forkpoint of parent chain ({parent.forkpoint}) "
            f"should be at lower height than children's ({forkpoint})"
        )
        with open(parent.path(), "rb") as f:
            f.seek((forkpoint - parent.forkpoint) * HEADER_SIZE)
            parent_data = f.read(parent_branch_size * HEADER_SIZE)
        self.write(parent_data, 0)
        parent.write(my_data, (forkpoint - parent.forkpoint) * HEADER_SIZE)
        self.parent, parent.parent = parent.parent, self
        self.forkpoint, parent.forkpoint = parent.forkpoint, self.forkpoint
        self._forkpoint_hash, parent._forkpoint_hash = (
            parent._forkpoint_hash,
            hash_raw_header(parent_data[:HEADER_SIZE]),
        )
        self._prev_hash, parent._prev_hash = parent._prev_hash, self._prev_hash
        os.replace(child_old_name, parent.path())
        self.update_size()
        parent.update_size()
        blockchains = self.bc_mgr.blockchains
        blockchains.pop(child_old_id, None)
        blockchains.pop(parent_old_id, None)
        blockchains[self.get_id()] = self
        blockchains[parent.get_id()] = parent
        return True

    def get_id(self) -> str:
        return self._forkpoint_hash

    def assert_headers_file_available(self, path: Path):
        if path.exists():
            return
        elif not self.bc_mgr.headers_dir.exists():
            raise FileNotFoundError(
                "headers_dir does not exist. Was it deleted while running?"
            )
        else:
            raise FileNotFoundError(
                "Cannot find headers file but headers_dir is there. Should be at {}".format(
                    path
                )
            )

    @with_lock
    def write(
        self, data: bytes, offset: int, truncate: bool = True, *, fsync: bool = True
    ) -> None:
        filename = self.path()
        self.assert_headers_file_available(filename)
        with open(filename, "rb+") as f:
            if truncate and offset != self._size * HEADER_SIZE:
                f.seek(offset)
                f.truncate()
            f.seek(offset)
            f.write(data)
            if fsync:
                f.flush()
                os.fsync(f.fileno())
        self.update_size()

    @with_lock
    def save_header(self, header: dict) -> None:
        delta = header.get("block_height") - self.forkpoint
        data = serialize_header(header)
        assert delta == self.size(), (delta, self.size())
        assert len(data) == HEADER_SIZE
        self.write(data, delta * HEADER_SIZE, fsync=False)
        self.swap_with_parent()

    @with_lock
    def read_header(self, height: int) -> dict | None:
        if height < 0:
            return
        if height < self.forkpoint:
            return self.parent.read_header(height)
        if height > self.height():
            return
        delta = height - self.forkpoint
        name = self.path()
        self.assert_headers_file_available(name)
        with open(name, "rb") as f:
            f.seek(delta * HEADER_SIZE)
            h = f.read(HEADER_SIZE)
            if len(h) < HEADER_SIZE:
                raise Exception(
                    "Expected to read a full header. This was only {} bytes".format(
                        len(h)
                    )
                )
        if h == bytes([0]) * HEADER_SIZE:
            return None
        return deserialize_header(h, height)

    def header_at_tip(self) -> dict | None:
        return self.read_header(self.height())

    def get_hash(self, height: int) -> str:
        def is_height_checkpoint():
            within_cp_range = height <= self.net.max_checkpoint()
            at_chunk_boundary = (height + 1) % CHUNK_SIZE == 0
            return within_cp_range and at_chunk_boundary

        if height == -1:
            return "0000000000000000000000000000000000000000000000000000000000000000"
        elif height == 0:
            return self.net.GENESIS
        elif is_height_checkpoint():
            index = height // CHUNK_SIZE
            return self.checkpoints[index][0]
        else:
            header = self.read_header(height)
            if header is None:
                raise MissingHeader(height)
            return hash_header(header)

    def get_timestamp(self, height: int) -> int | None:
        if (
            height < len(self.checkpoints) * CHUNK_SIZE
            and (height + 1) % CHUNK_SIZE == 0
        ):
            index = height // CHUNK_SIZE
            return self.checkpoints[index][2]
        header = self.read_header(height)
        return header.get("timestamp") if header else None

    def get_target(self, index: int) -> int:
        # compute target from chunk x, used in chunk x+1
        if self.net.TESTNET:
            return 0
        if index == -1:
            return self.net.FIRST_TARGET
        if index < len(self.checkpoints):
            return self.checkpoints[index][1]
        if self.net.timestamp_before_chunk:
            # Litecoin: go back the full period unless it's the first retarget
            first_timestamp = self.get_timestamp(
                index * CHUNK_SIZE - 1 if index > 0 else 0
            )
        else:
            first = self.read_header(index * CHUNK_SIZE)
            first_timestamp = first.get("timestamp") if first else None
        last = self.read_header((index + 1) * CHUNK_SIZE - 1)
        if not first_timestamp or not last:
            raise MissingHeader()
        bits = last.get("bits")
        target = self.bits_to_target(bits)
        nActualTimespan = last.get("timestamp") - first_timestamp
        nTargetTimespan = self.net.TARGET_TIMESPAN
        nActualTimespan = max(nActualTimespan, nTargetTimespan // 4)
        nActualTimespan = min(nActualTimespan, nTargetTimespan * 4)
        new_target = min(
            self.net.MAX_TARGET, (target * nActualTimespan) // nTargetTimespan
        )
        new_target = self.bits_to_target(self.target_to_bits(new_target))
        return new_target

    @classmethod
    def bits_to_target(cls, bits: int) -> int:
        if not (0 <= bits < (1 << 32)):
            raise InvalidHeader(f"bits should be uint32. got {bits!r}")
        bitsN = (bits >> 24) & 0xFF
        bitsBase = bits & 0x7FFFFF
        if bitsN <= 3:
            target = bitsBase >> (8 * (3 - bitsN))
        else:
            target = bitsBase << (8 * (bitsN - 3))
        if target != 0 and bits & 0x800000 != 0:
            raise InvalidHeader("target cannot be negative")
        if target != 0 and (
            bitsN > 34
            or (bitsN > 33 and bitsBase > 0xFF)
            or (bitsN > 32 and bitsBase > 0xFFFF)
        ):
            raise InvalidHeader("target has overflown")
        return target

    @classmethod
    def target_to_bits(cls, target: int) -> int:
        c = target.to_bytes(length=32, byteorder="big")
        bitsN = len(c)
        while bitsN > 0 and c[0] == 0:
            c = c[1:]
            bitsN -= 1
            if len(c) < 3:
                c += b"\x00"
        bitsBase = int.from_bytes(c[:3], byteorder="big")
        if bitsBase >= 0x800000:
            bitsN += 1
            bitsBase >>= 8
        return bitsN << 24 | bitsBase

    def chainwork_of_header_at_height(self, height: int) -> int:
        chunk_idx = height // CHUNK_SIZE - 1
        target = self.get_target(chunk_idx)
        work = ((2**256 - target - 1) // (target + 1)) + 1
        return work

    @with_lock
    def get_chainwork(self, height=None) -> int:
        if height is None:
            height = max(0, self.height())
        if self.net.TESTNET:
            return height
        cache = self.bc_mgr.chainwork_cache
        last_retarget = height // CHUNK_SIZE * CHUNK_SIZE - 1
        cached_height = last_retarget
        while cache.get(self.get_hash(cached_height)) is None:
            if cached_height <= -1:
                break
            cached_height -= CHUNK_SIZE
        assert cached_height >= -1, cached_height
        running_total = cache[self.get_hash(cached_height)]
        while cached_height < last_retarget:
            cached_height += CHUNK_SIZE
            work_in_single_header = self.chainwork_of_header_at_height(cached_height)
            work_in_chunk = CHUNK_SIZE * work_in_single_header
            running_total += work_in_chunk
            cache[self.get_hash(cached_height)] = running_total
        cached_height += CHUNK_SIZE
        work_in_single_header = self.chainwork_of_header_at_height(cached_height)
        work_in_last_partial_chunk = (height % CHUNK_SIZE + 1) * work_in_single_header
        return running_total + work_in_last_partial_chunk

    def can_connect(self, header: dict | None, *, check_height: bool = True) -> bool:
        if header is None:
            return False
        height = header["block_height"]
        if check_height and self.height() != height - 1:
            return False
        if height == 0:
            return hash_header(header) == self.net.GENESIS
        try:
            prev_hash = self.get_hash(height - 1)
        except Exception:
            return False
        if prev_hash != header.get("prev_block_hash"):
            return False
        try:
            target = self.get_target(height // CHUNK_SIZE - 1)
        except MissingHeader:
            return False
        try:
            self.verify_header(header, prev_hash, target)
        except BaseException:
            return False
        return True

    def connect_chunk(self, idx: int, data: bytes) -> bool:
        assert idx >= 0, idx
        try:
            self.verify_chunk(idx, data)
            self.save_chunk(idx, data)
            return True
        except BaseException as e:
            self.bc_mgr.log.info(f"verify_chunk idx {idx} failed: {repr(e)}")
            return False

    def get_checkpoints(self):
        cp = []
        n = self.height() // CHUNK_SIZE
        for index in range(n):
            h = self.get_hash((index + 1) * CHUNK_SIZE - 1)
            target = self.get_target(index)
            if self.net.timestamp_before_chunk:
                tstamp = self.get_timestamp((index + 1) * CHUNK_SIZE - 1)
                cp.append((h, target, tstamp))
            else:
                cp.append((h, target))
        return cp


class HeaderSync:
    def __init__(self, bc_mgr: BlockchainManager, server, log):
        self.bc_mgr = bc_mgr
        self.server = server
        self.log = log
        self.blockchain = bc_mgr.get_best_chain()
        self.tip = 0
        self.tip_header = None
        self._headers_cache = {}
        self._requested_chunks = set()

    def get_block_header(self, height: int, *, mode: str) -> dict:
        if not isinstance(height, int) or height < 0:
            raise Exception(f"{repr(height)} is not a block height")
        if raw_header := self._headers_cache.get(height):
            return deserialize_header(raw_header, height)
        if mode != ChainResolutionMode.CATCHUP:
            self.log.debug(f"requesting block header {height} in mode={mode}")
        res = self.server.call("blockchain.block.header", [height])
        return deserialize_header(bytes.fromhex(res), height)

    def get_block_headers(
        self, *, start_height: int, count: int, mode: str | None = None
    ) -> list:
        if not isinstance(start_height, int) or start_height < 0:
            raise Exception(f"{repr(start_height)} is not a block height")
        if not isinstance(count, int) or not (0 < count <= MAX_NUM_HEADERS_PER_REQUEST):
            raise Exception(
                f"{repr(count)} not an int in range ]0, {MAX_NUM_HEADERS_PER_REQUEST}]"
            )
        self.log.debug(
            f"requesting block headers: [{start_height}, {start_height + count - 1}], count={count}"
            + (f" (in mode={mode})" if mode is not None else "")
        )
        res = self.server.call("blockchain.block.headers", [start_height, count])
        if not isinstance(res, dict) or "count" not in res or "max" not in res:
            raise RequestCorrupted("block.headers reply lacks count or max")
        if not isinstance(res["count"], int) or res["count"] < 0:
            raise RequestCorrupted("block.headers count is not a non-negative int")
        if not isinstance(res["max"], int) or res["max"] < 0:
            raise RequestCorrupted("block.headers max is not a non-negative int")
        hex_headers_concat = res.get("hex")
        if not isinstance(hex_headers_concat, str):
            raise RequestCorrupted("block.headers reply lacks hex")
        if len(hex_headers_concat) != HEADER_SIZE * 2 * res["count"]:
            raise RequestCorrupted("inconsistent chunk hex and count")
        data = bytes.fromhex(hex_headers_concat)
        headers = [data[i : i + HEADER_SIZE] for i in range(0, len(data), HEADER_SIZE)]
        if res["max"] < MAX_NUM_HEADERS_PER_REQUEST:
            raise RequestCorrupted(
                f"server uses too low 'max' count for block.headers: {res['max']} < {MAX_NUM_HEADERS_PER_REQUEST}"
            )
        if res["count"] > count:
            raise RequestCorrupted(
                f"asked for {count} headers but got more: {res['count']}"
            )
        elif res["count"] < count:
            # we only tolerate getting fewer headers if it is due to reaching the tip
            end_height = start_height + res["count"] - 1
            if end_height < self.tip:
                raise RequestCorrupted(
                    f"asked for {count} headers but got fewer: {res['count']}. (start_height={start_height}, tip={self.tip})"
                )
        return headers

    def request_chunk_below_max_checkpoint(self, *, height: int) -> None:
        if not isinstance(height, int) or height < 0:
            raise Exception(f"{repr(height)} is not a block height")
        assert (
            height <= self.bc_mgr.net.max_checkpoint()
        ), f"height={height} must be <= cp={self.bc_mgr.net.max_checkpoint()}"
        index = height // CHUNK_SIZE
        if index in self._requested_chunks:
            return None
        self.log.debug(f"requesting chunk from height {height}")
        try:
            self._requested_chunks.add(index)
            headers = self.get_block_headers(
                start_height=index * CHUNK_SIZE, count=CHUNK_SIZE
            )
        finally:
            self._requested_chunks.discard(index)
        conn = self.blockchain.connect_chunk(index, data=b"".join(headers))
        if not conn:
            raise RequestCorrupted(
                f"chunk (index={index}, for height={height}) does not connect to blockchain"
            )
        return None

    def _fast_forward_chain(self, *, height: int, tip: int) -> int:
        max_checkpoint = self.bc_mgr.net.max_checkpoint()
        if not (height > max_checkpoint or height == 0 == max_checkpoint):
            raise Exception(f"height={height} must be > cp={max_checkpoint}")
        assert height <= tip, f"height={height} must be <= tip={tip}"
        index0 = height // CHUNK_SIZE
        num_headers = 0
        for chunk_cnt in range(10):
            index = index0 + chunk_cnt
            start_height = index * CHUNK_SIZE
            if start_height > tip:
                break
            end_height = min(start_height + CHUNK_SIZE - 1, tip)
            size = end_height - start_height + 1
            headers = self.get_block_headers(start_height=start_height, count=size)
            conn = self.blockchain.connect_chunk(index, data=b"".join(headers))
            if not conn:
                break
            num_headers += len(headers)
        # We started at a chunk boundary, instead of requested `height`
        offset = height - index0 * CHUNK_SIZE
        return max(0, num_headers - offset)

    def process_header_at_tip(self, height: int, header: dict) -> bool:
        if height < self.bc_mgr.net.max_checkpoint():
            raise ChainConflict(
                f"server tip below max checkpoint. ({height} < {self.bc_mgr.net.max_checkpoint()})"
            )
        self.tip_header = header
        self.tip = height
        self._headers_cache.clear()
        self._headers_cache[height] = serialize_header(header)
        try:
            with self.bc_mgr.bhi_lock:
                if self.blockchain.height() >= height and self.blockchain.check_header(
                    header
                ):
                    return False
                self.sync_until(height)
                return True
        finally:
            self._headers_cache.clear()

    def sync_until(self, height: int, *, next_height: int | None = None):
        if next_height is None:
            next_height = self.tip
        last = None
        while last is None or height <= next_height:
            prev_last, prev_height = last, height
            if next_height > height + 144:
                num_headers = self._fast_forward_chain(height=height, tip=next_height)
                if num_headers == 0:
                    if height <= self.bc_mgr.net.max_checkpoint():
                        raise ChainConflict(
                            "server chain conflicts with checkpoints or genesis"
                        )
                    last, height = self.step(height)
                    continue
                height += num_headers
                assert height <= next_height + 1, (height, self.tip)
                last = ChainResolutionMode.CATCHUP
            else:
                last, height = self.step(height)
            assert (prev_last, prev_height) != (
                last,
                height,
            ), "had to prevent infinite loop in interface.sync_until"
        return last, height

    def step(self, height: int):
        assert 0 <= height <= self.tip, (height, self.tip)
        self._maybe_warm_headers_cache(
            from_height=height,
            to_height=min(self.tip, height + MAX_NUM_HEADERS_PER_REQUEST - 1),
            mode=ChainResolutionMode.CATCHUP,
        )
        header = self.get_block_header(height, mode=ChainResolutionMode.CATCHUP)

        chain = self.bc_mgr.check_header(header)
        if chain:
            self.blockchain = chain
            return ChainResolutionMode.CATCHUP, height + 1

        can_connect = self.bc_mgr.can_connect(header)
        if not can_connect:
            self.log.info(f"can't connect new block: height={height}")
            height, header, bad, bad_header = self._search_headers_backwards(
                height, header=header
            )
            chain = self.bc_mgr.check_header(header)
            can_connect = self.bc_mgr.can_connect(header)
            assert chain or can_connect
        if can_connect:
            height += 1
            self.blockchain = can_connect
            self.blockchain.save_header(header)
            return ChainResolutionMode.CATCHUP, height

        good, bad, bad_header = self._search_headers_binary(
            height, bad, bad_header, chain
        )
        return self._resolve_potential_chain_fork_given_forkpoint(good, bad, bad_header)

    def _search_headers_binary(self, height: int, bad: int, bad_header: dict, chain):
        assert bad == bad_header["block_height"]
        self._assert_header_does_not_check_against_any_chain(bad_header)

        self.blockchain = chain
        good = height
        while True:
            assert 0 <= good < bad, (good, bad)
            height = (good + bad) // 2
            self.log.info(f"binary step. good {good}, bad {bad}, height {height}")
            if bad - good + 1 <= MAX_NUM_HEADERS_PER_REQUEST:
                self._maybe_warm_headers_cache(
                    from_height=good, to_height=bad, mode=ChainResolutionMode.BINARY
                )
            header = self.get_block_header(height, mode=ChainResolutionMode.BINARY)
            chain = self.bc_mgr.check_header(header)
            if chain:
                self.blockchain = chain
                good = height
            else:
                bad = height
                bad_header = header
            if good + 1 == bad:
                break

        if not self.blockchain.can_connect(bad_header, check_height=False):
            raise Exception(
                "unexpected bad header during binary: {}".format(bad_header)
            )
        self._assert_header_does_not_check_against_any_chain(bad_header)

        self.log.info(f"binary search exited. good {good}, bad {bad}")
        return good, bad, bad_header

    def _resolve_potential_chain_fork_given_forkpoint(
        self, good: int, bad: int, bad_header: dict
    ):
        assert good + 1 == bad
        assert bad == bad_header["block_height"]
        self._assert_header_does_not_check_against_any_chain(bad_header)

        bh = self.blockchain.height()
        assert bh >= good, (bh, good)
        if bh == good:
            height = good + 1
            self.log.info(f"catching up from {height}")
            return ChainResolutionMode.NO_FORK, height

        height = bad + 1
        self.log.info(f"new fork at bad height {bad}")
        b = self.blockchain.fork(bad_header)
        self.blockchain = b
        assert b.forkpoint == bad
        return ChainResolutionMode.FORK, height

    def _search_headers_backwards(self, height: int, *, header: dict):
        max_checkpoint = self.bc_mgr.net.max_checkpoint()

        def iterate():
            nonlocal height, header
            checkp = False
            if height <= max_checkpoint:
                height = max_checkpoint
                checkp = True
            header = self.get_block_header(height, mode=ChainResolutionMode.BACKWARD)
            chain = self.bc_mgr.check_header(header)
            can_connect = self.bc_mgr.can_connect(header)
            if chain or can_connect:
                return False
            if checkp:
                raise ChainConflict("server chain conflicts with checkpoints")
            return True

        bad, bad_header = height, header
        self._assert_header_does_not_check_against_any_chain(bad_header)
        with self.bc_mgr.blockchains_lock:
            chains = list(self.bc_mgr.blockchains.values())
        local_max = max([0] + [x.height() for x in chains])
        height = min(local_max + 1, height - 1)
        assert height >= 0

        self._maybe_warm_headers_cache(
            from_height=max(0, height - 10),
            to_height=height,
            mode=ChainResolutionMode.BACKWARD,
        )

        delta = 2
        while iterate():
            bad, bad_header = height, header
            height -= delta
            delta *= 2

        self._assert_header_does_not_check_against_any_chain(bad_header)
        self.log.info(f"exiting backward mode at {height}")
        return height, header, bad, bad_header

    def _maybe_warm_headers_cache(
        self, *, from_height: int, to_height: int, mode: str
    ) -> None:
        assert from_height <= to_height, (from_height, to_height)
        assert to_height - from_height < MAX_NUM_HEADERS_PER_REQUEST
        if all(
            height in self._headers_cache
            for height in range(from_height, to_height + 1)
        ):
            return
        count = to_height - from_height + 1
        headers = self.get_block_headers(
            start_height=from_height, count=count, mode=mode
        )
        for idx, raw_header in enumerate(headers):
            self._headers_cache[from_height + idx] = raw_header

    def _assert_header_does_not_check_against_any_chain(self, header: dict) -> None:
        chain_bad = self.bc_mgr.check_header(header)
        if chain_bad:
            raise Exception("bad_header must not check!")


class SerializationError(Exception):
    pass


class BCDataStream:
    def __init__(self, data: bytes):
        self.input = data
        self.read_cursor = 0

    def read_bytes(self, length: int) -> bytes:
        assert length >= 0
        read_begin = self.read_cursor
        read_end = read_begin + length
        if 0 <= read_begin <= read_end <= len(self.input):
            self.read_cursor += length
            return bytes(self.input[read_begin:read_end])
        raise SerializationError("attempt to read past end of buffer")

    def read_compact_size(self) -> int:
        size = self.read_bytes(1)[0]
        if size == 253:
            return int.from_bytes(self.read_bytes(2), "little")
        if size == 254:
            return int.from_bytes(self.read_bytes(4), "little")
        if size == 255:
            return int.from_bytes(self.read_bytes(8), "little")
        return size

    def can_read_more(self) -> bool:
        return self.read_cursor < len(self.input)


def deserialize_tx(raw: bytes) -> None:
    vds = BCDataStream(raw)
    vds.read_bytes(4)
    n_vin = vds.read_compact_size()
    is_segwit = n_vin == 0
    if is_segwit:
        marker = vds.read_bytes(1)
        if marker != b"\x01":
            raise SerializationError("invalid txn marker byte: {}".format(marker))
        n_vin = vds.read_compact_size()
    if n_vin < 1:
        raise SerializationError("tx needs to have at least 1 input")
    for _ in range(n_vin):
        vds.read_bytes(32 + 4)
        vds.read_bytes(vds.read_compact_size())
        vds.read_bytes(4)
    n_vout = vds.read_compact_size()
    if n_vout < 1:
        raise SerializationError("tx needs to have at least 1 output")
    for _ in range(n_vout):
        if int.from_bytes(vds.read_bytes(8), "little", signed=True) < 0:
            raise SerializationError("invalid output amount (negative)")
        vds.read_bytes(vds.read_compact_size())
    if is_segwit:
        for _ in range(n_vin):
            for _ in range(vds.read_compact_size()):
                vds.read_bytes(vds.read_compact_size())
    vds.read_bytes(4)
    if vds.can_read_more():
        raise SerializationError("extra junk at the end")


def is_valid_tx(raw: bytes) -> bool:
    try:
        deserialize_tx(raw)
    except Exception:
        return False
    return True


def hash_merkle_root(
    merkle_branch: list, tx_hash: str, leaf_pos_in_tree: int, is_valid_tx
) -> str:
    try:
        h = hash_decode(tx_hash)
        merkle_branch_bytes = [hash_decode(item) for item in merkle_branch]
        leaf_pos_in_tree = int(leaf_pos_in_tree)
    except Exception as e:
        raise MerkleVerificationFailure(e)
    if leaf_pos_in_tree < 0:
        raise MerkleVerificationFailure("leaf_pos_in_tree must be non-negative")
    index = leaf_pos_in_tree
    for sibling in merkle_branch_bytes:
        if len(sibling) != 32:
            raise MerkleVerificationFailure(
                "all merkle branch items have to be 32 bytes long"
            )
        is_right_child = index & 1
        inner_node = (sibling + h) if is_right_child else (h + sibling)
        # CVE-2017-12842 protection: inner node must not be a valid tx
        if is_valid_tx(inner_node):
            raise InnerNodeOfSpvProofIsValidTx()
        # CVE-2012-2459 protection: reject left-sibling duplicates
        if is_right_child and sibling == h:
            raise LeftSiblingDuplicate()
        h = sha256d(inner_node)
        index >>= 1
    if index != 0:
        raise MerkleVerificationFailure("leaf_pos_in_tree too large for branch")
    return hash_encode(h)


def verify_tx_is_in_block(
    tx_hash: str,
    merkle_branch: list,
    leaf_pos_in_tree: int,
    block_header: dict | None,
    block_height: int,
    is_valid_tx,
) -> None:
    if not block_header:
        raise MissingBlockHeader(
            "merkle verification failed for {} (missing header {})".format(
                tx_hash, block_height
            )
        )
    if len(merkle_branch) > 30:
        raise MerkleVerificationFailure(f"merkle branch too long: {len(merkle_branch)}")
    calc_merkle_root = hash_merkle_root(
        merkle_branch, tx_hash, leaf_pos_in_tree, is_valid_tx
    )
    if block_header.get("merkle_root") != calc_merkle_root:
        raise MerkleRootMismatch(
            "merkle verification failed for {} ({} != {})".format(
                tx_hash, block_header.get("merkle_root"), calc_merkle_root
            )
        )
