# -*- coding: utf-8 -*-

# Copyright (c) 2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import json

from basicswap.db import getOrderByStr


class UIApp:
    def listMessageRoutes(self, filters={}, action=None):
        cursor = self.openDB()
        try:
            rv = []

            query_data: dict = {}
            filter_query_str: str = ""
            address_from: str = filters.get("address_from", None)
            if address_from is not None:
                filter_query_str += " AND smsg_addr_local = :address_from "
                query_data["address_from"] = address_from

            address_to: str = filters.get("address_to", None)
            if address_from is not None:
                filter_query_str += " AND smsg_addr_remote = :address_to "
                query_data["address_to"] = address_to

            if action is None:
                pass
            elif action == "clear":
                self.log.info("Clearing message routes")
                query_str: str = (
                    "SELECT record_id, network_id, route_data"
                    + " FROM direct_message_routes "
                    + " WHERE active_ind = 1 "
                )
                query_str += filter_query_str
                rows = cursor.execute(query_str, query_data).fetchall()
                for row in rows:
                    record_id, network_id, route_data = row
                    route_data = json.loads(route_data.decode("UTF-8"))
                    self.closeMessageRoute(record_id, network_id, route_data, cursor)

            else:
                raise ValueError("Unknown action")

            query_str: str = (
                "SELECT record_id, network_id, linked_type, linked_id, "
                + "       smsg_addr_local, smsg_addr_remote, route_data, created_at"
                + " FROM direct_message_routes "
                + " WHERE active_ind = 1 "
            )

            query_str += filter_query_str
            query_str += getOrderByStr(filters)

            limit = filters.get("limit", None)
            if limit is not None:
                query_str += " LIMIT :limit"
                query_data["limit"] = limit
            offset = filters.get("offset", None)
            if offset is not None:
                query_str += " OFFSET :offset"
                query_data["offset"] = offset

            q = cursor.execute(query_str, query_data)
            rv = []
            for row in q:
                (
                    record_id,
                    network_id,
                    linked_type,
                    linked_id,
                    smsg_addr_local,
                    smsg_addr_remote,
                    route_data,
                    created_at,
                ) = row
                rv.append(
                    {
                        "record_id": record_id,
                        "network_id": network_id,
                        "smsg_addr_local": smsg_addr_local,
                        "smsg_addr_remote": smsg_addr_remote,
                        "route_data": json.loads(route_data.decode("UTF-8")),
                    }
                )

            return rv
        finally:
            self.closeDB(cursor, commit=False)
