# -*- coding: utf-8 -*-

# Copyright (c) 2022-2023 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import json

from .util import (
    PAGE_LIMIT,
    get_data_entry,
    get_data_entry_or,
    have_data_entry,
    set_pagination_filters,
)
from basicswap.util import (
    ensure,
)
from basicswap.db import (
    strConcepts,
)


def page_automation_strategies(self, url_split, post_string):
    server = self.server
    swap_client = server.swap_client
    swap_client.checkSystemStatus()
    summary = swap_client.getSummary()

    filters = {
        'page_no': 1,
        'limit': PAGE_LIMIT,
        'sort_by': 'created_at',
        'sort_dir': 'desc',
    }

    messages = []
    form_data = self.checkForm(post_string, 'automationstrategies', messages)

    if form_data:
        if have_data_entry(form_data, 'clearfilters'):
            swap_client.clearFilters('page_automation_strategies')
        else:
            if have_data_entry(form_data, 'sort_by'):
                sort_by = get_data_entry(form_data, 'sort_by')
                ensure(sort_by in ['created_at', 'rate'], 'Invalid sort by')
                filters['sort_by'] = sort_by
            if have_data_entry(form_data, 'sort_dir'):
                sort_dir = get_data_entry(form_data, 'sort_dir')
                ensure(sort_dir in ['asc', 'desc'], 'Invalid sort dir')
                filters['sort_dir'] = sort_dir

            set_pagination_filters(form_data, filters)
        if have_data_entry(form_data, 'applyfilters'):
            swap_client.setFilters('page_automation_strategies', filters)
    else:
        saved_filters = swap_client.getFilters('page_automation_strategies')
        if saved_filters:
            filters.update(saved_filters)

    formatted_strategies = []
    for s in swap_client.listAutomationStrategies(filters):
        formatted_strategies.append((s[0], s[1], strConcepts(s[2])))

    template = server.env.get_template('automation_strategies.html')
    return self.render_template(template, {
        'messages': messages,
        'filters': filters,
        'strategies': formatted_strategies,
        'summary': summary,
    })


def page_automation_strategy_new(self, url_split, post_string):
    server = self.server
    swap_client = self.server.swap_client
    swap_client.checkSystemStatus()
    summary = swap_client.getSummary()

    messages = []
    form_data = self.checkForm(post_string, 'automationstrategynew', messages)

    template = server.env.get_template('automation_strategy_new.html')
    return self.render_template(template, {
        'messages': messages,
        'summary': summary,
    })


def page_automation_strategy(self, url_split, post_string):
    ensure(len(url_split) > 2, 'Strategy ID not specified')
    try:
        strategy_id = int(url_split[2])
    except Exception:
        raise ValueError('Bad strategy ID')

    server = self.server
    swap_client = server.swap_client
    swap_client.checkSystemStatus()
    summary = swap_client.getSummary()

    messages = []
    err_messages = []
    form_data = self.checkForm(post_string, 'automation_strategy', err_messages)
    show_edit_form = False
    if form_data:
        if have_data_entry(form_data, 'edit'):
            show_edit_form = True
        if have_data_entry(form_data, 'apply'):
            try:
                data = json.loads(get_data_entry_or(form_data, 'data', ''))
                note = get_data_entry_or(form_data, 'note', '')
                swap_client.updateAutomationStrategy(strategy_id, data, note)
                messages.append('Updated')
            except Exception as e:
                err_messages.append(str(e))
                show_edit_form = True

    strategy = swap_client.getAutomationStrategy(strategy_id)

    formatted_strategy = {
        'label': strategy.label,
        'type': strConcepts(strategy.type_ind),
        'only_known_identities': 'True' if strategy.only_known_identities is True else 'False',
        'data': strategy.data.decode('utf-8'),
        'note': '' if not strategy.note else strategy.note,
        'created_at': strategy.created_at,
    }

    template = server.env.get_template('automation_strategy.html')
    return self.render_template(template, {
        'messages': messages,
        'err_messages': err_messages,
        'strategy': formatted_strategy,
        'show_edit_form': show_edit_form,
        'summary': summary,
    })
