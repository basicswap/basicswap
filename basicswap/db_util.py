# -*- coding: utf-8 -*-

# Copyright (c) 2023-2025 The Basicswap Developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from .db import (
    Concepts,
)


def remove_expired_data(self, time_offset: int = 0):
    now: int = self.getTime()
    try:
        cursor = self.openDB()

        # Only remove expired offers that carry no bids, so completed swaps and
        # any other bid history are never discarded along with their offer.
        offers_query = """
                    SELECT o.offer_id FROM offers o
                    WHERE o.expire_at <= :expired_at
                      AND NOT EXISTS (SELECT 1 FROM bids b WHERE b.offer_id = o.offer_id)
                    LIMIT :batch_size
                    """
        batch_size: int = 500
        num_offers = 0
        while True:
            # Read the batch out before deleting: the deletes below run on the
            # same cursor and would discard a partly-read result set.
            offer_rows = cursor.execute(
                offers_query,
                {"expired_at": now - time_offset, "batch_size": batch_size},
            ).fetchall()
            if len(offer_rows) < 1:
                break
            for offer_row in offer_rows:
                num_offers += 1
                offer_query_data = {
                    "type_ind": int(Concepts.OFFER),
                    "offer_id": offer_row[0],
                }
                for query_str in [
                    "DELETE FROM eventlog WHERE eventlog.linked_type = :type_ind AND eventlog.linked_id = :offer_id",
                    "DELETE FROM automationlinks WHERE automationlinks.linked_type = :type_ind AND automationlinks.linked_id = :offer_id",
                    "DELETE FROM prefunded_transactions WHERE prefunded_transactions.linked_type = :type_ind AND prefunded_transactions.linked_id = :offer_id",
                    "DELETE FROM history WHERE history.concept_type = :type_ind AND history.concept_id = :offer_id",
                    "DELETE FROM xmr_offers WHERE xmr_offers.offer_id = :offer_id",
                    "DELETE FROM sentoffers WHERE sentoffers.offer_id = :offer_id",
                    "DELETE FROM actions WHERE actions.linked_id = :offer_id",
                    "DELETE FROM offers WHERE offers.offer_id = :offer_id",
                    "DELETE FROM message_links WHERE linked_type = :type_ind AND linked_id = :offer_id",
                    "DELETE FROM message_network_links WHERE linked_type = :type_ind AND linked_id = :offer_id",
                ]:
                    cursor.execute(query_str, offer_query_data)
            if len(offer_rows) < batch_size:
                break

        if num_offers > 0:
            self.log.info(
                "Removed data for {} expired offer{}.".format(
                    num_offers,
                    "s" if num_offers != 1 else "",
                )
            )

        cursor.execute(
            "DELETE FROM checkedblocks WHERE created_at <= :expired_at",
            {"expired_at": now - time_offset},
        )

    finally:
        self.closeDB(cursor)
