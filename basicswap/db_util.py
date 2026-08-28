# -*- coding: utf-8 -*-

# Copyright (c) 2023-2026 The Basicswap Developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from .db import (
    Concepts,
)


def remove_expired_data(
    self, time_offset: int = 0, unused_offers_only: bool = False
) -> None:
    now: int = self.getTime()
    try:
        cursor = self.openDB()

        if unused_offers_only:
            # Offers that expired without ever receiving a bid.  The bid deletes
            # below match nothing for these, only the offer rows are removed.
            offers_filter: str = (
                "NOT EXISTS (SELECT 1 FROM bids b2 WHERE b2.offer_id = o.offer_id)"
            )
        else:
            active_bids_insert: str = self.activeBidsQueryStr("", "b2")
            offers_filter = f"0 = (SELECT COUNT(*) FROM bids b2 WHERE b2.offer_id = o.offer_id AND {active_bids_insert})"

        batch_size: int = 500
        max_batches: int = 100
        query_data = {
            "offer_type_ind": int(Concepts.OFFER),
            "bid_type_ind": int(Concepts.BID),
            "now": now,
            "expired_at": now - time_offset,
            "batch_size": batch_size,
        }

        # ORDER BY keeps the batch identical across the statements below, which
        # each re-evaluate the subquery.  offer_id is the primary key.
        expired_offers: str = f"""SELECT o.offer_id FROM offers o
                    WHERE o.expire_at <= :expired_at AND {offers_filter}
                    ORDER BY o.offer_id LIMIT :batch_size"""
        expired_bids: str = (
            f"SELECT bid_id FROM bids WHERE offer_id IN ({expired_offers})"
        )

        num_offers: int = 0
        num_bids: int = 0
        # Cap the work per call so a large backlog drains over several passes of
        # the main loop instead of holding mxDB for the whole prune.
        for _ in range(max_batches):
            num_bids += list(
                cursor.execute(
                    f"SELECT COUNT(*) FROM bids WHERE offer_id IN ({expired_offers})",
                    query_data,
                )
            )[0][0]

            # Each list must run before the rows its subquery reads are removed,
            # so bids and offers are always deleted last.
            for query_str in [
                f"DELETE FROM transactions WHERE transactions.bid_id IN ({expired_bids})",
                f"DELETE FROM eventlog WHERE eventlog.linked_type = :bid_type_ind AND eventlog.linked_id IN ({expired_bids})",
                f"DELETE FROM automationlinks WHERE automationlinks.linked_type = :bid_type_ind AND automationlinks.linked_id IN ({expired_bids})",
                f"DELETE FROM prefunded_transactions WHERE prefunded_transactions.linked_type = :bid_type_ind AND prefunded_transactions.linked_id IN ({expired_bids})",
                f"DELETE FROM history WHERE history.concept_type = :bid_type_ind AND history.concept_id IN ({expired_bids})",
                f"DELETE FROM xmr_swaps WHERE xmr_swaps.bid_id IN ({expired_bids})",
                f"DELETE FROM actions WHERE actions.linked_id IN ({expired_bids})",
                f"DELETE FROM addresspool WHERE addresspool.bid_id IN ({expired_bids})",
                f"DELETE FROM xmr_split_data WHERE xmr_split_data.bid_id IN ({expired_bids})",
                f"DELETE FROM message_links WHERE linked_type = :bid_type_ind AND linked_id IN ({expired_bids})",
                f"DELETE FROM direct_message_route_links WHERE linked_type = :bid_type_ind AND linked_id IN ({expired_bids})",
                f"DELETE FROM message_network_links WHERE linked_type = :bid_type_ind AND linked_id IN ({expired_bids})",
                f"DELETE FROM bids WHERE offer_id IN ({expired_offers})",
                f"DELETE FROM eventlog WHERE eventlog.linked_type = :offer_type_ind AND eventlog.linked_id IN ({expired_offers})",
                f"DELETE FROM automationlinks WHERE automationlinks.linked_type = :offer_type_ind AND automationlinks.linked_id IN ({expired_offers})",
                f"DELETE FROM prefunded_transactions WHERE prefunded_transactions.linked_type = :offer_type_ind AND prefunded_transactions.linked_id IN ({expired_offers})",
                f"DELETE FROM history WHERE history.concept_type = :offer_type_ind AND history.concept_id IN ({expired_offers})",
                f"DELETE FROM xmr_offers WHERE xmr_offers.offer_id IN ({expired_offers})",
                f"DELETE FROM sentoffers WHERE sentoffers.offer_id IN ({expired_offers})",
                f"DELETE FROM actions WHERE actions.linked_id IN ({expired_offers})",
                f"DELETE FROM message_links WHERE linked_type = :offer_type_ind AND linked_id IN ({expired_offers})",
                f"DELETE FROM direct_message_route_links WHERE linked_type = :offer_type_ind AND linked_id IN ({expired_offers})",
                f"DELETE FROM message_network_links WHERE linked_type = :offer_type_ind AND linked_id IN ({expired_offers})",
            ]:
                cursor.execute(query_str, query_data)

            cursor.execute(
                f"DELETE FROM offers WHERE offer_id IN ({expired_offers})", query_data
            )
            num_offers += cursor.rowcount
            if cursor.rowcount < batch_size:
                break

        if num_offers > 0 or num_bids > 0:
            self.log.info(
                "Removed data for {} expired {}{} and {} bid{}.".format(
                    num_offers,
                    "unused offer" if unused_offers_only else "offer",
                    "s" if num_offers != 1 else "",
                    num_bids,
                    "s" if num_bids != 1 else "",
                )
            )

        if not unused_offers_only:
            cursor.execute(
                "DELETE FROM checkedblocks WHERE created_at <= :expired_at",
                {"expired_at": now - time_offset},
            )

    finally:
        self.closeDB(cursor)
