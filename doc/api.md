

Examples:

    curl --header "Content-Type: application/json" \
         --request POST \
         --data '{"coin_from":"btc","coin_to":"xmr","amt_from":10,"amt_to":10,"lockseconds":1200}' \
         http://localhost:12701/json/offers/new

    curl --header "Content-Type: application/json" \
         --request POST \
         --data '{"show_extra":true}' \
         http://localhost:12701/json/bids/00000000636ab87a5c8950b66684e86b5ed3684f175c8d05a8f0bfb6

    curl --header "Content-Type: application/json" \
         --request POST \
         --data '{"coin_from":"xmr","coin_to":"btc","receive_amount":1.5,"max_bids":5,"anchor":"market","slip_percent":2}' \
         http://localhost:12701/json/bids/plan

    curl --header "Content-Type: application/json" \
         --request POST \
         --data '{"legs":[{"offer_id":"000000006ac12dec174631c1201b4e0c02a07b8dc73a50b1ad77747b","amount":"0.9"},{"offer_id":"000000006ac12e032ec84be3f7db1298edde63adfc13fe4692fdcbfb","amount":"0.6"}],"validmins":60,"plan_leg_timeout":10}' \
         http://localhost:12701/json/bids/bulk
