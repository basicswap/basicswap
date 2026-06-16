# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.contrib.test_framework.messages import COIN
from basicswap.db import (
    Concepts,
    strConcepts,
)
from basicswap.util import toBool as make_boolean


class FeeValidator:
    @staticmethod
    def defaultMaxFeeRate() -> int:
        return COIN // 10

    def __init__(self, **kwargs):
        self.updateFeeValidationSettings(kwargs.get("network"))
        super().__init__(**kwargs)

    def makeIntFromSetting(
        self, settings: dict, setting_name: str, default: int
    ) -> int:
        # Return make_int(setting), or already integer default
        if setting_name in settings:
            return self.make_int(settings[setting_name])
        return default

    def updateFeeValidationSettings(self, network: str) -> None:
        default_low_fee_conf_target: int = 24
        default_low_fee_rate: int = 0
        default_low_estimated_feerate_multiplier: float = 0.8
        default_high_estimated_feerate_multiplier: float = 4.0
        default_high_fee_rate: int = self.defaultMaxFeeRate()
        default_allow_highfee_offers_when_minfee_src: bool = True
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
            default_low_estimated_feerate_multiplier = float(
                settings.get(
                    "low_estimated_feerate_multiplier",
                    default_low_estimated_feerate_multiplier,
                )
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
            default_allow_highfee_offers_when_minfee_src = make_boolean(
                settings.get(
                    "allow_highfee_offers_when_minfee_src",
                    default_allow_highfee_offers_when_minfee_src,
                )
            )
        else:
            if network != "regtest":
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

        self._low_estimated_feerate_multiplier = float(
            chain_client_settings.get(
                "low_estimated_feerate_multiplier",
                default_low_estimated_feerate_multiplier,
            )
        )
        if self._low_estimated_feerate_multiplier < 0.0:
            raise ValueError("low_estimated_feerate_multiplier can't be negative")

        # Set below 1.0 to disable estimating the max feerate and use max_feerate
        self._high_estimated_feerate_multiplier = float(
            chain_client_settings.get(
                "high_estimated_feerate_multiplier",
                default_high_estimated_feerate_multiplier,
            )
        )
        if self._high_estimated_feerate_multiplier < 0.0:
            raise ValueError("high_estimated_feerate_multiplier can't be negative")

        self._high_feerate = self.makeIntFromSetting(
            chain_client_settings, "high_feerate", default_high_fee_rate
        )

        self._allow_highfee_offers_when_minfee = make_boolean(
            chain_client_settings.get(
                "allow_highfee_offers_when_minfee_src",
                default_allow_highfee_offers_when_minfee_src,
            )
        )

    def getHardMinFee(self):  # -> (float, str) | (None, None):
        chain_client_settings = self._sc.getChainClientSettings(
            self.coin_type()
        )  # basicswap.json
        override_feerate = chain_client_settings.get("override_feerate", None)
        if override_feerate:
            self._log.debug(
                f"Fee rate override used for {self.coin_name()}: {override_feerate}"
            )
            return override_feerate, "override_feerate"
        if "min_relay_fee" in chain_client_settings:
            return chain_client_settings["min_relay_fee"], "min_relay_fee_setting"

        if self._connection_type == "rpc":
            networkinfo = self.rpc("getnetworkinfo")
            if "relayfee" in networkinfo:
                return networkinfo["relayfee"], "relayfee_rpc"
        return None, None

    def validateFeeRate(self, feerate: int, concept_type: int) -> None:
        if self._low_feerate > 0:
            min_feerate, min_feerate_src = (self._low_feerate, "set_value")
            hard_min_feerate, hard_min_feerate_src = (None, None)
        else:
            min_feerate_float, min_feerate_src = self.get_fee_rate(
                self._low_fee_conf_target
            )
            min_feerate = self.make_int(min_feerate_float)
            hard_min_feerate_float, hard_min_feerate_src = self.getHardMinFee()
            hard_min_feerate = (
                None
                if hard_min_feerate_float is None
                else self.make_int(hard_min_feerate_float)
            )

        # If the hard minfeerate is known reduce the minfeerate
        if hard_min_feerate is not None and min_feerate_src in (
            "estimatesmartfee",
            "electrum",
        ):
            min_feerate = max(
                hard_min_feerate,
                int(min_feerate * self._low_estimated_feerate_multiplier),
            )

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

        concept_name: str = strConcepts(concept_type)
        min_fee_rate_desc: str = f"min {min_feerate} {min_feerate_src}"
        if hard_min_feerate is not None and hard_min_feerate != min_feerate:
            min_fee_rate_desc += f" (hardmin {hard_min_feerate} {hard_min_feerate_src})"

        self._log.debug(
            f"Verify {self.ticker()} fee rate {feerate} for {concept_name}, {min_fee_rate_desc}, max {max_feerate} {max_feerate_src}"
        )
        if feerate < min_feerate:
            err_msg: str = (
                f"Fee rate too low, {feerate} < {min_feerate}, {min_feerate_src}"
            )
            self._log.error(err_msg)
            raise ValueError(err_msg)

        if feerate > max_feerate:
            # If validating for an offer, allow high fees if estimate source is relayfee
            # Fee will be validated again on sending bid
            if concept_type == Concepts.OFFER and self._allow_highfee_offers_when_minfee:
                if max_feerate_src in ("relayfee", "min_relay_fee"):
                    self._log.debug(
                        "Allowing offer through as max feerate source is minfee"
                    )
                    return

            err_msg: str = (
                f"Fee rate too high, {feerate} > {max_feerate}, {max_feerate_src}"
            )
            self._log.error(err_msg)
            raise ValueError(err_msg)
