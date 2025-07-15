#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2024 tecnovert
# Copyright (c) 2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.


"""
syntax = "proto3";

0 VARINT int32, int64, uint32, uint64, sint32, sint64, bool, enum
1 I64 fixed64, sfixed64, double
2 LEN string, bytes, embedded messages, packed repeated fields
5 I32 fixed32, sfixed32, float

Don't encode fields of default values.
When decoding initialise all fields not set from data.

protobuf ParseFromString would reset the whole object, from_bytes won't.
"""

from basicswap.util.integer import encode_varint, decode_varint


NPBW_INT = 0
NPBW_BYTES = 2

NPBF_STR = 1
NPBF_BOOL = 2


class NonProtobufClass:
    def __init__(self, init_all: bool = True, **kwargs):
        for key, value in kwargs.items():
            found_field: bool = False
            for field_num, v in self._map.items():
                field_name, wire_type, field_type = v
                if field_name == key:
                    setattr(self, field_name, value)
                    found_field = True
                    break
            if found_field is False:
                raise ValueError(f"Got an unexpected keyword argument '{key}'")

        if init_all:
            self.init_fields()

    def init_fields(self) -> None:
        # Set default values for missing fields
        for field_num, v in self._map.items():
            field_name, wire_type, field_type = v
            if hasattr(self, field_name):
                continue
            if wire_type == 0:
                setattr(self, field_name, 0)
            elif wire_type == 2:
                if field_type == 1:
                    setattr(self, field_name, str())
                else:
                    setattr(self, field_name, bytes())
            else:
                raise ValueError(f"Unknown wire_type {wire_type}")

    def to_bytes(self) -> bytes:
        rv = bytes()

        for field_num, v in self._map.items():
            field_name, wire_type, field_type = v
            if not hasattr(self, field_name):
                continue
            field_value = getattr(self, field_name)
            tag = (field_num << 3) | wire_type
            if wire_type == 0:
                if field_value == 0:
                    continue
                rv += encode_varint(tag)
                rv += encode_varint(field_value)
            elif wire_type == 2:
                if len(field_value) == 0:
                    continue
                rv += encode_varint(tag)
                if isinstance(field_value, str):
                    field_value = field_value.encode("utf-8")
                rv += encode_varint(len(field_value))
                rv += field_value
            else:
                raise ValueError(f"Unknown wire_type {wire_type}")
        return rv

    def from_bytes(self, b: bytes, init_all: bool = True) -> None:
        max_len: int = len(b)
        o: int = 0
        while o < max_len:
            tag, lv = decode_varint(b, o)
            o += lv
            wire_type = tag & 7
            field_num = tag >> 3

            field_name, wire_type_expect, field_type = self._map[field_num]
            if wire_type != wire_type_expect:
                raise ValueError(
                    f"Unexpected wire_type {wire_type} for field {field_num}"
                )

            if wire_type == 0:
                field_value, lv = decode_varint(b, o)
                o += lv
            elif wire_type == 2:
                field_len, lv = decode_varint(b, o)
                o += lv
                field_value = b[o : o + field_len]
                o += field_len
                if field_type == 1:
                    field_value = field_value.decode("utf-8")
            else:
                raise ValueError(f"Unknown wire_type {wire_type}")

            setattr(self, field_name, field_value)

        if init_all:
            self.init_fields()


class OfferMessage(NonProtobufClass):
    _map = {
        1: ("protocol_version", NPBW_INT, 0),
        2: ("coin_from", NPBW_INT, 0),
        3: ("coin_to", NPBW_INT, 0),
        4: ("amount_from", NPBW_INT, 0),
        5: ("amount_to", NPBW_INT, 0),
        6: ("min_bid_amount", NPBW_INT, 0),
        7: ("time_valid", NPBW_INT, 0),
        8: ("lock_type", NPBW_INT, 0),
        9: ("lock_value", NPBW_INT, 0),
        10: ("swap_type", NPBW_INT, 0),
        11: ("proof_address", NPBW_BYTES, NPBF_STR),
        12: ("proof_signature", NPBW_BYTES, NPBF_STR),
        13: ("pkhash_seller", NPBW_BYTES, 0),
        14: ("secret_hash", NPBW_BYTES, 0),
        15: ("fee_rate_from", NPBW_INT, 0),
        16: ("fee_rate_to", NPBW_INT, 0),
        17: ("amount_negotiable", NPBW_INT, NPBF_BOOL),
        18: ("rate_negotiable", NPBW_INT, NPBF_BOOL),
        19: ("proof_utxos", NPBW_BYTES, 0),
        20: ("auto_accept_type", NPBW_INT, 0),
        21: ("message_nets", NPBW_BYTES, NPBF_STR),
    }


class BidMessage(NonProtobufClass):
    _map = {
        1: ("protocol_version", NPBW_INT, 0),
        2: ("offer_msg_id", NPBW_BYTES, 0),
        3: ("time_valid", NPBW_INT, 0),
        4: ("amount", NPBW_INT, 0),
        5: ("amount_to", NPBW_INT, 0),
        6: ("pkhash_buyer", NPBW_BYTES, 0),
        7: ("proof_address", NPBW_BYTES, NPBF_STR),
        8: ("proof_signature", NPBW_BYTES, NPBF_STR),
        9: ("proof_utxos", NPBW_BYTES, 0),
        10: ("pkhash_buyer_to", NPBW_BYTES, 0),
        11: ("message_nets", NPBW_BYTES, NPBF_STR),
    }


class BidAcceptMessage(NonProtobufClass):
    # Step 3, seller -> buyer
    _map = {
        1: ("bid_msg_id", NPBW_BYTES, 0),
        2: ("initiate_txid", NPBW_BYTES, 0),
        3: ("contract_script", NPBW_BYTES, 0),
        4: ("pkhash_seller", NPBW_BYTES, 0),
    }


class OfferRevokeMessage(NonProtobufClass):
    _map = {
        1: ("offer_msg_id", NPBW_BYTES, 0),
        2: ("signature", NPBW_BYTES, 0),
    }


class BidRejectMessage(NonProtobufClass):
    _map = {
        1: ("bid_msg_id", NPBW_BYTES, 0),
        2: ("reject_code", NPBW_INT, 0),
    }


class XmrBidMessage(NonProtobufClass):
    # MSG1L, F -> L
    _map = {
        1: ("protocol_version", NPBW_INT, 0),
        2: ("offer_msg_id", NPBW_BYTES, 0),
        3: ("time_valid", NPBW_INT, 0),
        4: ("amount", NPBW_INT, 0),
        5: ("amount_to", NPBW_INT, 0),
        6: ("pkaf", NPBW_BYTES, 0),
        7: ("kbvf", NPBW_BYTES, 0),
        8: ("kbsf_dleag", NPBW_BYTES, 0),
        9: ("dest_af", NPBW_BYTES, 0),
        10: ("message_nets", NPBW_BYTES, NPBF_STR),
    }


class XmrSplitMessage(NonProtobufClass):
    _map = {
        1: ("msg_id", NPBW_BYTES, 0),
        2: ("msg_type", NPBW_INT, 0),
        3: ("sequence", NPBW_INT, 0),
        4: ("dleag", NPBW_BYTES, 0),
    }


class XmrBidAcceptMessage(NonProtobufClass):
    _map = {
        1: ("bid_msg_id", NPBW_BYTES, 0),
        2: ("pkal", NPBW_BYTES, 0),
        3: ("kbvl", NPBW_BYTES, 0),
        4: ("kbsl_dleag", NPBW_BYTES, 0),
        # MSG2F
        5: ("a_lock_tx", NPBW_BYTES, 0),
        6: ("a_lock_tx_script", NPBW_BYTES, 0),
        7: ("a_lock_refund_tx", NPBW_BYTES, 0),
        8: ("a_lock_refund_tx_script", NPBW_BYTES, 0),
        9: ("a_lock_refund_spend_tx", NPBW_BYTES, 0),
        10: ("al_lock_refund_tx_sig", NPBW_BYTES, 0),
    }


class XmrBidLockTxSigsMessage(NonProtobufClass):
    # MSG3L
    _map = {
        1: ("bid_msg_id", NPBW_BYTES, 0),
        2: ("af_lock_refund_spend_tx_esig", NPBW_BYTES, 0),
        3: ("af_lock_refund_tx_sig", NPBW_BYTES, 0),
    }


class XmrBidLockSpendTxMessage(NonProtobufClass):
    # MSG4F
    _map = {
        1: ("bid_msg_id", NPBW_BYTES, 0),
        2: ("a_lock_spend_tx", NPBW_BYTES, 0),
        3: ("kal_sig", NPBW_BYTES, 0),
    }


class XmrBidLockReleaseMessage(NonProtobufClass):
    # MSG5F
    _map = {
        1: ("bid_msg_id", NPBW_BYTES, 0),
        2: ("al_lock_spend_tx_esig", NPBW_BYTES, 0),
    }


class ADSBidIntentMessage(NonProtobufClass):
    # L -> F Sent from bidder, construct a reverse bid
    _map = {
        1: ("protocol_version", NPBW_INT, 0),
        2: ("offer_msg_id", NPBW_BYTES, 0),
        3: ("time_valid", NPBW_INT, 0),
        4: ("amount_from", NPBW_INT, 0),
        5: ("amount_to", NPBW_INT, 0),
        6: ("message_nets", NPBW_BYTES, NPBF_STR),
    }


class ADSBidIntentAcceptMessage(NonProtobufClass):
    # F -> L Sent from offerer, construct a reverse bid
    _map = {
        1: ("bid_msg_id", NPBW_BYTES, 0),
        2: ("pkaf", NPBW_BYTES, 0),
        3: ("kbvf", NPBW_BYTES, 0),
        4: ("kbsf_dleag", NPBW_BYTES, 0),
        5: ("dest_af", NPBW_BYTES, 0),
    }


class ConnectReqMessage(NonProtobufClass):
    _map = {
        1: ("network_type", NPBW_INT, 0),
        2: ("network_data", NPBW_BYTES, 0),
        3: ("request_type", NPBW_INT, 0),
        4: ("request_data", NPBW_BYTES, 0),
    }


class MessagePortalOffer(NonProtobufClass):
    _map = {
        1: ("network_type_from", NPBW_INT, 0),
        2: ("network_type_to", NPBW_INT, 0),
        3: ("portal_address_from", NPBW_BYTES, 0),
        4: ("portal_address_to", NPBW_BYTES, 0),
        5: ("time_valid", NPBW_INT, 0),
        6: ("smsg_difficulty", NPBW_INT, 0),
    }


class MessagePortalSend(NonProtobufClass):
    _map = {
        1: ("forward_address", NPBW_BYTES, 0),  # pubkey, 33 bytes
        2: ("message_bytes", NPBW_BYTES, 0),
    }
