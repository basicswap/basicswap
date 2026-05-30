# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.contrib.test_framework.messages import COIN


class FeeValidator:
    @staticmethod
    def defaultMaxFeeRate() -> int:
        return COIN // 10

    def makeIntFromSetting(
        self, settings: dict, setting_name: str, default: int
    ) -> int:
        # Return make_int(setting), or already integer default
        if setting_name in settings:
            return self.make_int(settings[setting_name])
        return default

    def __init__(self, **kwargs):
        default_low_fee_conf_target: int = 24
        default_low_fee_rate: int = 0
        default_high_estimated_feerate_multiplier: float = 4.0
        default_high_fee_rate: int = self.defaultMaxFeeRate()
        if self._sc:
            chain_client_settings = self._sc.getChainClientSettings(
                self.coin_type()
            )  # basicswap.json
            settings = self._sc.settings
            default_low_fee_conf_target = int(
                settings.get("low_fee_conf_target", default_low_fee_conf_target)
            )
            default_low_fee_rate = self.makeIntFromSetting(
                settings, "low_feerate", default_low_fee_rate
            )
            default_high_estimated_feerate_multiplier = float(
                settings.get(
                    "high_estimated_feerate_multiplier",
                    default_high_estimated_feerate_multiplier,
                )
            )
            default_high_fee_rate = self.makeIntFromSetting(
                settings, "high_feerate", default_high_fee_rate
            )
        else:
            if kwargs.get("network") != "regtest":
                raise ValueError("swapclient unset")
            chain_client_settings = {}

        self._low_fee_conf_target = int(
            chain_client_settings.get(
                "low_fee_conf_target", default_low_fee_conf_target
            )
        )
        self._low_feerate = self.makeIntFromSetting(
            chain_client_settings, "low_feerate", default_low_fee_rate
        )

        # Set below 1.0 to disable estimating the max feerate and use max_feerate
        self._high_estimated_feerate_multiplier = float(
            chain_client_settings.get(
                "high_estimated_feerate_multiplier",
                default_high_estimated_feerate_multiplier,
            )
        )
        self._high_feerate = self.makeIntFromSetting(
            chain_client_settings, "high_feerate", default_high_fee_rate
        )

        super().__init__(**kwargs)

    def validateFeeRate(self, feerate: int) -> None:
        if self._low_feerate > 0:
            min_feerate_src = "set_value"
            min_feerate = self._low_feerate
        else:
            min_feerate, min_feerate_src = self.get_fee_rate(self._low_fee_conf_target)
            min_feerate = self.make_int(min_feerate)

        if self._high_estimated_feerate_multiplier >= 1.0:
            max_feerate, max_feerate_src = self.get_fee_rate()
            max_feerate = int(
                self.make_int(max_feerate) * self._high_estimated_feerate_multiplier
            )
        else:
            max_feerate_src = "set_value"
            max_feerate = self._high_feerate

        if max_feerate_src in ("estimatesmartfee", "electrum"):
            if max_feerate > self._high_feerate:
                max_feerate_src = "clamped_to_set_value"
                max_feerate = self._high_feerate

        self._log.debug(
            f"Verify {self.ticker()} fee rate {feerate}, min {min_feerate} {min_feerate_src}, max {max_feerate} {max_feerate_src}"
        )
        if feerate < min_feerate:
            err_msg: str = (
                f"Fee rate too low, {feerate} < {min_feerate}, {min_feerate_src}"
            )
            self._log.error(err_msg)
            raise ValueError(err_msg)
        if feerate > max_feerate:
            err_msg: str = (
                f"Fee rate too high, {feerate} > {max_feerate}, {max_feerate_src}"
            )
            self._log.error(err_msg)
            raise ValueError(err_msg)
