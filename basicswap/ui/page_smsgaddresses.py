# -*- coding: utf-8 -*-

# Copyright (c) 2023 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.


from .util import (
    PAGE_LIMIT,
    get_data_entry,
    have_data_entry,
    get_data_entry_or,
    validateTextInput,
    set_pagination_filters,
)
from basicswap.util import (
    ensure,
)
from basicswap.basicswap_util import (
    AddressTypes,
    strAddressType,
)


def page_smsgaddresses(self, url_split, post_string):
    swap_client = self.server.swap_client
    swap_client.checkSystemStatus()
    summary = swap_client.getSummary()

    filters = {
        'page_no': 1,
        'limit': PAGE_LIMIT,
        'sort_by': 'created_at',
        'sort_dir': 'desc',
        'addr_type': -1,
    }

    page_data = {}
    messages = []
    err_messages = []
    smsgaddresses = []

    listaddresses = True
    form_data = self.checkForm(post_string, 'smsgaddresses', err_messages)
    if form_data:
        edit_address_id = None
        for key in form_data:
            if key.startswith(b'editaddr_'):
                edit_address_id = int(key.split(b'_')[1])
                break
        if edit_address_id is not None:
            listaddresses = False
            page_data['edit_address'] = edit_address_id
            page_data['addr_data'] = swap_client.listAllSMSGAddresses({'addr_id': edit_address_id})[0]
        elif have_data_entry(form_data, 'saveaddr'):
            edit_address_id = int(get_data_entry(form_data, 'edit_address_id'))
            edit_addr = get_data_entry(form_data, 'edit_address')
            active_ind = int(get_data_entry(form_data, 'active_ind'))
            ensure(active_ind in (0, 1), 'Invalid sort by')
            addressnote = get_data_entry_or(form_data, 'addressnote', '')
            if not validateTextInput(addressnote, 'Address note', err_messages, max_length=30):
                listaddresses = False
                page_data['edit_address'] = edit_address_id
            else:
                swap_client.editSMSGAddress(edit_addr, active_ind=active_ind, addressnote=addressnote)
                messages.append(f'Edited address {edit_addr}')
        elif have_data_entry(form_data, 'shownewaddr'):
            listaddresses = False
            page_data['new_address'] = True
        elif have_data_entry(form_data, 'showaddaddr'):
            listaddresses = False
            page_data['new_send_address'] = True
        elif have_data_entry(form_data, 'createnewaddr'):
            addressnote = get_data_entry_or(form_data, 'addressnote', '')
            if not validateTextInput(addressnote, 'Address note', err_messages, max_length=30):
                listaddresses = False
                page_data['new_address'] = True
            else:
                new_addr, pubkey = swap_client.newSMSGAddress(addressnote=addressnote)
                messages.append(f'Created address {new_addr}, pubkey {pubkey}')
        elif have_data_entry(form_data, 'createnewsendaddr'):
            pubkey_hex = get_data_entry(form_data, 'addresspubkey')
            addressnote = get_data_entry_or(form_data, 'addressnote', '')
            if not validateTextInput(addressnote, 'Address note', messages, max_length=30) or \
               not validateTextInput(pubkey_hex, 'Pubkey', messages, max_length=66):
                listaddresses = False
                page_data['new_send_address'] = True
            else:
                new_addr = swap_client.addSMSGAddress(pubkey_hex, addressnote=addressnote)
                messages.append(f'Added address {new_addr}')

        if have_data_entry(form_data, 'clearfilters'):
            swap_client.clearFilters('page_smsgaddresses')
        else:
            if have_data_entry(form_data, 'sort_by'):
                sort_by = get_data_entry(form_data, 'sort_by')
                ensure(sort_by in ['created_at', 'rate'], 'Invalid sort by')
                filters['sort_by'] = sort_by
            if have_data_entry(form_data, 'sort_dir'):
                sort_dir = get_data_entry(form_data, 'sort_dir')
                ensure(sort_dir in ['asc', 'desc'], 'Invalid sort dir')
                filters['sort_dir'] = sort_dir
            if have_data_entry(form_data, 'filter_addressnote'):
                addressnote = get_data_entry(form_data, 'filter_addressnote')
                if validateTextInput(addressnote, 'Address note', err_messages, max_length=30):
                    filters['addressnote'] = addressnote
            if have_data_entry(form_data, 'filter_addr_type'):
                filters['addr_type'] = int(get_data_entry(form_data, 'filter_addr_type'))

            set_pagination_filters(form_data, filters)
        if have_data_entry(form_data, 'applyfilters'):
            swap_client.setFilters('page_smsgaddresses', filters)
    else:
        saved_filters = swap_client.getFilters('page_smsgaddresses')
        if saved_filters:
            filters.update(saved_filters)

    if listaddresses is True:
        smsgaddresses = swap_client.listAllSMSGAddresses(filters)

        page_data['addr_types'] = [(int(t), strAddressType(t)) for t in AddressTypes]
        page_data['network_addr'] = swap_client.network_addr

    for addr in smsgaddresses:
        addr['type'] = strAddressType(addr['type'])

    template = self.server.env.get_template('smsgaddresses.html')
    return self.render_template(template, {
        'messages': messages,
        'err_messages': err_messages,
        'filters': filters,
        'data': page_data,
        'smsgaddresses': smsgaddresses,
        'page_data': page_data,
        'summary': summary,
    })
