# -*- coding: utf-8 -*-

# Copyright (c) 2022-2023 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import html

from .util import (
    getCoinName,
    get_data_entry,
    have_data_entry,
    get_data_entry_or,
)
from basicswap.util import (
    toBool,
    InactiveCoin,
)
from basicswap.chainparams import (
    Coins,
)


def page_settings(self, url_split, post_string):
    server = self.server
    swap_client = server.swap_client
    swap_client.checkSystemStatus()

    messages = []
    err_messages = []
    active_tab = 'default'
    form_data = self.checkForm(post_string, 'settings', err_messages)
    if form_data:
        try:
            if have_data_entry(form_data, 'apply_general'):
                active_tab = 'general'
                data = {
                    'debug': toBool(get_data_entry(form_data, 'debugmode')),
                    'debug_ui': toBool(get_data_entry(form_data, 'debugui')),
                    'expire_db_records': toBool(get_data_entry(form_data, 'expire_db_records')),
                }
                swap_client.editGeneralSettings(data)
            elif have_data_entry(form_data, 'apply_chart'):
                active_tab = 'general'
                data = {
                    'show_chart': toBool(get_data_entry(form_data, 'showchart')),
                    'chart_api_key': html.unescape(get_data_entry_or(form_data, 'chartapikey', '')),
                }
                swap_client.editGeneralSettings(data)
            elif have_data_entry(form_data, 'apply_tor'):
                active_tab = 'tor'
                # TODO: Detect if running in docker
                raise ValueError('TODO: If running in docker see doc/tor.md to enable/disable tor.')

            for name, c in swap_client.settings['chainclients'].items():
                if have_data_entry(form_data, 'apply_' + name):
                    data = {'lookups': get_data_entry(form_data, 'lookups_' + name)}
                    if name in ['haven', 'monero']:
                        data['fee_priority'] = int(get_data_entry(form_data, 'fee_priority_' + name))
                        data['manage_daemon'] = True if get_data_entry(form_data, 'managedaemon_' + name) == 'true' else False
                        data['rpchost'] = get_data_entry(form_data, 'rpchost_' + name)
                        data['rpcport'] = int(get_data_entry(form_data, 'rpcport_' + name))
                        data['remotedaemonurls'] = get_data_entry_or(form_data, 'remotedaemonurls_' + name, '')
                        data['automatically_select_daemon'] = True if get_data_entry(form_data, 'autosetdaemon_' + name) == 'true' else False
                    else:
                        data['conf_target'] = int(get_data_entry(form_data, 'conf_target_' + name))
                        if name == 'particl':
                            data['anon_tx_ring_size'] = int(get_data_entry(form_data, 'rct_ring_size_' + name))

                    settings_changed, suggest_reboot = swap_client.editSettings(name, data)
                    if settings_changed is True:
                        messages.append('Settings applied.')
                    if suggest_reboot is True:
                        messages.append('Please restart BasicSwap.')
                elif have_data_entry(form_data, 'enable_' + name):
                    swap_client.enableCoin(name)
                    display_name = getCoinName(swap_client.getCoinIdFromName(name))
                    messages.append(display_name + ' enabled, shutting down.')
                    swap_client.stopRunning()
                elif have_data_entry(form_data, 'disable_' + name):
                    swap_client.disableCoin(name)
                    display_name = getCoinName(swap_client.getCoinIdFromName(name))
                    messages.append(display_name + ' disabled, shutting down.')
                    swap_client.stopRunning()
        except InactiveCoin as ex:
            err_messages.append('InactiveCoin {}'.format(Coins(ex.coinid).name))
        except Exception as e:
            err_messages.append(str(e))
    chains_formatted = []

    sorted_names = sorted(swap_client.settings['chainclients'].keys())
    for name in sorted_names:
        c = swap_client.settings['chainclients'][name]
        try:
            display_name = getCoinName(swap_client.getCoinIdFromName(name))
        except Exception:
            display_name = name
        chains_formatted.append({
            'name': name,
            'display_name': display_name,
            'lookups': c.get('chain_lookups', 'local'),
            'manage_daemon': c.get('manage_daemon', 'Unknown'),
            'connection_type': c.get('connection_type', 'Unknown'),
        })
        if name in ['haven', 'monero']:
            chains_formatted[-1]['fee_priority'] = c.get('fee_priority', 0)
            chains_formatted[-1]['manage_wallet_daemon'] = c.get('manage_wallet_daemon', 'Unknown')
            chains_formatted[-1]['rpchost'] = c.get('rpchost', 'localhost')
            chains_formatted[-1]['rpcport'] = int(c.get('rpcport', 18081))
            chains_formatted[-1]['remotedaemonurls'] = '\n'.join(c.get('remote_daemon_urls', []))
            chains_formatted[-1]['autosetdaemon'] = c.get('automatically_select_daemon', False)
        else:
            chains_formatted[-1]['conf_target'] = c.get('conf_target', 2)

        if name == 'particl':
            chains_formatted[-1]['anon_tx_ring_size'] = c.get('anon_tx_ring_size', 12)
        else:
            if c.get('connection_type', 'Unknown') == 'none':
                if 'connection_type_prev' in c:
                    chains_formatted[-1]['can_reenable'] = True
            else:
                chains_formatted[-1]['can_disable'] = True

    general_settings = {
        'debug': swap_client.debug,
        'debug_ui': swap_client.debug_ui,
        'expire_db_records': swap_client._expire_db_records,
    }
    if 'chart_api_key_enc' in swap_client.settings:
        chart_api_key = html.escape(bytes.fromhex(swap_client.settings.get('chart_api_key_enc', '')).decode('utf-8'))
    else:
        chart_api_key = swap_client.settings.get('chart_api_key', '')
    chart_settings = {
        'show_chart': swap_client.settings.get('show_chart', True),
        'chart_api_key': chart_api_key,
    }

    tor_control_password = '' if swap_client.tor_control_password is None else swap_client.tor_control_password
    tor_settings = {
        'use_tor': swap_client.use_tor_proxy,
        'proxy_host': swap_client.tor_proxy_host,
        'proxy_port': swap_client.tor_proxy_port,
        'control_password': html.escape(tor_control_password),
        'control_port': swap_client.tor_control_port,
    }

    template = server.env.get_template('settings.html')
    return self.render_template(template, {
        'messages': messages,
        'err_messages': err_messages,
        'summary': swap_client.getSummary(),
        'chains': chains_formatted,
        'general_settings': general_settings,
        'chart_settings': chart_settings,
        'tor_settings': tor_settings,
        'active_tab': active_tab,
    })
