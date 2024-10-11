# -*- coding: utf-8 -*-

# Copyright (c) 2023-2024 The BSX Developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from sqlalchemy.sql import text
from .db import (
    Concepts,
)


def remove_expired_data(self, time_offset: int = 0):
    now: int = self.getTime()
    try:
        session = self.openSession()

        active_bids_insert = self.activeBidsQueryStr(now, '', 'b2')
        query_str = f'''
                    SELECT o.offer_id FROM offers o
                    WHERE o.expire_at <= :expired_at AND 0 = (SELECT COUNT(*) FROM bids b2 WHERE b2.offer_id = o.offer_id AND {active_bids_insert})
                    '''
        num_offers = 0
        num_bids = 0
        offer_rows = session.execute(text(query_str), {'expired_at': now - time_offset})
        for offer_row in offer_rows:
            num_offers += 1
            bid_rows = session.execute(text('SELECT bids.bid_id FROM bids WHERE bids.offer_id = :offer_id'), {'offer_id': offer_row[0]})
            for bid_row in bid_rows:
                num_bids += 1
                session.execute(text('DELETE FROM transactions WHERE transactions.bid_id = :bid_id'), {'bid_id': bid_row[0]})
                session.execute(text('DELETE FROM eventlog WHERE eventlog.linked_type = :type_ind AND eventlog.linked_id = :bid_id'), {'type_ind': int(Concepts.BID), 'bid_id': bid_row[0]})
                session.execute(text('DELETE FROM automationlinks WHERE automationlinks.linked_type = :type_ind AND automationlinks.linked_id = :bid_id'), {'type_ind': int(Concepts.BID), 'bid_id': bid_row[0]})
                session.execute(text('DELETE FROM prefunded_transactions WHERE prefunded_transactions.linked_type = :type_ind AND prefunded_transactions.linked_id = :bid_id'), {'type_ind': int(Concepts.BID), 'bid_id': bid_row[0]})
                session.execute(text('DELETE FROM history WHERE history.concept_type = :type_ind AND history.concept_id = :bid_id'), {'type_ind': int(Concepts.BID), 'bid_id': bid_row[0]})
                session.execute(text('DELETE FROM xmr_swaps WHERE xmr_swaps.bid_id = :bid_id'), {'bid_id': bid_row[0]})
                session.execute(text('DELETE FROM actions WHERE actions.linked_id = :bid_id'), {'bid_id': bid_row[0]})
                session.execute(text('DELETE FROM addresspool WHERE addresspool.bid_id = :bid_id'), {'bid_id': bid_row[0]})
                session.execute(text('DELETE FROM xmr_split_data WHERE xmr_split_data.bid_id = :bid_id'), {'bid_id': bid_row[0]})
                session.execute(text('DELETE FROM bids WHERE bids.bid_id = :bid_id'), {'bid_id': bid_row[0]})
                session.execute(text('DELETE FROM message_links WHERE linked_type = :type_ind AND linked_id = :linked_id'), {'type_ind': int(Concepts.BID), 'linked_id': bid_row[0]})

            session.execute(text('DELETE FROM eventlog WHERE eventlog.linked_type = :type_ind AND eventlog.linked_id = :offer_id'), {'type_ind': int(Concepts.OFFER), 'offer_id': offer_row[0]})
            session.execute(text('DELETE FROM automationlinks WHERE automationlinks.linked_type = :type_ind AND automationlinks.linked_id = :offer_id'), {'type_ind': int(Concepts.OFFER), 'offer_id': offer_row[0]})
            session.execute(text('DELETE FROM prefunded_transactions WHERE prefunded_transactions.linked_type = :type_ind AND prefunded_transactions.linked_id = :offer_id'), {'type_ind': int(Concepts.OFFER), 'offer_id': offer_row[0]})
            session.execute(text('DELETE FROM history WHERE history.concept_type = :type_ind AND history.concept_id = :offer_id'), {'type_ind': int(Concepts.OFFER), 'offer_id': offer_row[0]})
            session.execute(text('DELETE FROM xmr_offers WHERE xmr_offers.offer_id = :offer_id'), {'offer_id': offer_row[0]})
            session.execute(text('DELETE FROM sentoffers WHERE sentoffers.offer_id = :offer_id'), {'offer_id': offer_row[0]})
            session.execute(text('DELETE FROM actions WHERE actions.linked_id = :offer_id'), {'offer_id': offer_row[0]})
            session.execute(text('DELETE FROM offers WHERE offers.offer_id = :offer_id'), {'offer_id': offer_row[0]})
            session.execute(text('DELETE FROM message_links WHERE linked_type = :type_ind AND linked_id = :offer_id'), {'type_ind': int(Concepts.OFFER), 'offer_id': offer_row[0]})

        if num_offers > 0 or num_bids > 0:
            self.log.info('Removed data for {} expired offer{} and {} bid{}.'.format(num_offers, 's' if num_offers != 1 else '', num_bids, 's' if num_bids != 1 else ''))

        session.execute(text('DELETE FROM checkedblocks WHERE created_at <= :expired_at'), {'expired_at': now - time_offset})

    finally:
        self.closeSession(session)
