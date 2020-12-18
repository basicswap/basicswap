import unittest

import tests.basicswap.test_other as test_other
import tests.basicswap.test_prepare as test_prepare
import tests.basicswap.test_run as test_run
import tests.basicswap.test_reload as test_reload


def test_suite():
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(test_other)
    suite.addTests(loader.loadTestsFromModule(test_prepare))
    suite.addTests(loader.loadTestsFromModule(test_run))
    suite.addTests(loader.loadTestsFromModule(test_reload))
    # TODO: Add to ci scripts suite.addTests(loader.loadTestsFromModule(test_xmr))

    return suite
