

Examples:

    curl --header "Content-Type: application/json" \
         --request POST \
         --data '{"coin_from":"btc","coin_to":"xmr","amt_from":10,"amt_to":10,"lockseconds":1200}' \
         http://localhost:12701/json/offers/new

    curl --header "Content-Type: application/json" \
         --request POST \
         --data '{"show_extra":true}' \
         http://localhost:12701/json/bids/00000000636ab87a5c8950b66684e86b5ed3684f175c8d05a8f0bfb6
